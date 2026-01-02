/**
 * Mediator Node Boundary Integration
 *
 * Provides boundary daemon integration for the mediator-node,
 * which performs LLM mediation and mining operations.
 *
 * Key integration points:
 * - LLM API calls require network permission
 * - Mining operations may require specific modes
 * - Mediation content is checked for policy compliance
 */

import * as net from 'net';
import * as fs from 'fs';
import * as path from 'path';

export enum BoundaryMode {
  OPEN = 'open',
  RESTRICTED = 'restricted',
  TRUSTED = 'trusted',
  AIRGAP = 'airgap',
  COLDROOM = 'coldroom',
  LOCKDOWN = 'lockdown',
}

export interface PolicyDecision {
  permitted: boolean;
  reason: string;
  mode?: BoundaryMode;
}

export interface MediationCheckResult extends PolicyDecision {
  contentFlags?: string[];
  suggestedMode?: BoundaryMode;
}

function getSocketPath(): string {
  const paths = [
    process.env.BOUNDARY_DAEMON_SOCKET,
    '/var/run/boundary-daemon/boundary.sock',
    path.join(process.env.HOME || '~', '.agent-os/api/boundary.sock'),
    './api/boundary.sock',
  ];

  for (const p of paths) {
    if (p && fs.existsSync(p)) {
      return p;
    }
  }

  return '/var/run/boundary-daemon/boundary.sock';
}

export class BoundaryClient {
  private socketPath: string;
  private token?: string;
  private timeout: number;

  constructor(config: { socketPath?: string; token?: string; timeout?: number } = {}) {
    this.socketPath = config.socketPath || getSocketPath();
    this.token = config.token || process.env.BOUNDARY_API_TOKEN;
    this.timeout = config.timeout ?? 5000;
  }

  private async sendRequest(command: string, params: Record<string, any> = {}): Promise<Record<string, any>> {
    const request: Record<string, any> = { command, params };
    if (this.token) {
      request.token = this.token;
    }

    return new Promise((resolve, reject) => {
      const client = net.createConnection({ path: this.socketPath }, () => {
        client.write(JSON.stringify(request));
      });

      client.setTimeout(this.timeout);

      let data = '';
      client.on('data', (chunk) => { data += chunk.toString(); });
      client.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error(`Invalid JSON: ${data}`));
        }
      });
      client.on('error', reject);
      client.on('timeout', () => {
        client.destroy();
        reject(new Error('Timeout'));
      });
    });
  }

  async getMode(): Promise<BoundaryMode> {
    try {
      const response = await this.sendRequest('status');
      return (response.status?.mode || 'lockdown').toLowerCase() as BoundaryMode;
    } catch {
      return BoundaryMode.LOCKDOWN;
    }
  }

  async checkLLMCall(modelName: string): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_tool', {
        tool_name: `llm:${modelName}`,
        requires_network: true,
      });

      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
      };
    } catch {
      return {
        permitted: false,
        reason: 'Boundary daemon unavailable - fail closed',
      };
    }
  }

  async checkMediationContent(content: string, context?: Record<string, any>): Promise<MediationCheckResult> {
    try {
      const response = await this.sendRequest('check_message', {
        content,
        source: 'mediator-node',
        context: {
          type: 'mediation',
          ...context,
        },
      });

      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
        contentFlags: response.result?.flags,
        suggestedMode: response.result?.suggested_mode,
      };
    } catch {
      return {
        permitted: false,
        reason: 'Boundary daemon unavailable - fail closed',
      };
    }
  }

  async checkMiningOperation(operationType: string): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_tool', {
        tool_name: `mining:${operationType}`,
        requires_network: true,
        requires_filesystem: true,
      });

      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
      };
    } catch {
      return {
        permitted: false,
        reason: 'Boundary daemon unavailable - fail closed',
      };
    }
  }
}

/**
 * LLM Mediation Gate.
 *
 * Controls access to LLM API calls for mediation.
 */
export class MediationGate {
  private client: BoundaryClient;
  private lastDecision?: PolicyDecision;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): PolicyDecision | undefined {
    return this.lastDecision;
  }

  async canCallLLM(modelName: string): Promise<boolean> {
    this.lastDecision = await this.client.checkLLMCall(modelName);
    return this.lastDecision.permitted;
  }

  async canMediate(content: string, context?: Record<string, any>): Promise<boolean> {
    this.lastDecision = await this.client.checkMediationContent(content, context);
    return this.lastDecision.permitted;
  }

  async requireLLMPermission(modelName: string): Promise<void> {
    const canCall = await this.canCallLLM(modelName);
    if (!canCall) {
      throw new Error(`LLM call to '${modelName}' denied: ${this.lastDecision?.reason}`);
    }
  }
}

/**
 * Mining Gate.
 *
 * Controls mining operations.
 */
export class MiningGate {
  private client: BoundaryClient;
  private lastDecision?: PolicyDecision;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): PolicyDecision | undefined {
    return this.lastDecision;
  }

  async canMine(operationType: string): Promise<boolean> {
    this.lastDecision = await this.client.checkMiningOperation(operationType);
    return this.lastDecision.permitted;
  }

  async requireMiningPermission(operationType: string): Promise<void> {
    const canMine = await this.canMine(operationType);
    if (!canMine) {
      throw new Error(`Mining operation '${operationType}' denied: ${this.lastDecision?.reason}`);
    }
  }
}

/**
 * Main integration class for mediator-node.
 */
export class MediatorBoundaryIntegration {
  public readonly mediationGate: MediationGate;
  public readonly miningGate: MiningGate;
  private client: BoundaryClient;

  constructor() {
    this.client = new BoundaryClient();
    this.mediationGate = new MediationGate(this.client);
    this.miningGate = new MiningGate(this.client);
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.client.getMode();
      return true;
    } catch {
      return false;
    }
  }

  async getMode(): Promise<BoundaryMode> {
    return this.client.getMode();
  }

  async canConnectToNatLangChain(): Promise<PolicyDecision> {
    // NatLangChain connection requires network
    return this.client.checkLLMCall('natlangchain');
  }

  /**
   * Wrap an LLM call with boundary enforcement.
   */
  async withLLMBoundary<T>(
    modelName: string,
    callFn: () => Promise<T>,
    fallback?: () => Promise<T>
  ): Promise<T | undefined> {
    const canCall = await this.mediationGate.canCallLLM(modelName);

    if (canCall) {
      return callFn();
    }

    if (fallback) {
      console.log(`LLM '${modelName}' denied, using fallback`);
      return fallback();
    }

    return undefined;
  }
}

/**
 * Create a boundary-protected LLM client.
 */
export function createProtectedLLMClient<T>(
  client: T,
  modelName: string
): T {
  const boundary = new MediatorBoundaryIntegration();

  // Return a proxy that checks permissions before each call
  return new Proxy(client as any, {
    get(target, prop) {
      const original = target[prop];

      if (typeof original === 'function') {
        return async (...args: any[]) => {
          await boundary.mediationGate.requireLLMPermission(modelName);
          return original.apply(target, args);
        };
      }

      return original;
    },
  });
}

export default MediatorBoundaryIntegration;
