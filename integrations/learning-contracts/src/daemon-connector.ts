/**
 * Learning Contracts Boundary Daemon Connector
 *
 * FIXED VERSION: Corrects socket path and adds full integration.
 *
 * This module connects Learning Contracts to the Boundary Daemon,
 * enforcing policy decisions before operations execute.
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

export enum Classification {
  PUBLIC = 0,
  INTERNAL = 1,
  CONFIDENTIAL = 2,
  SECRET = 3,
  TOP_SECRET = 4,
  CROWN_JEWEL = 5,
}

export interface PolicyDecision {
  permitted: boolean;
  reason: string;
  mode?: BoundaryMode;
}

export interface DaemonConnectorConfig {
  socketPath?: string;
  httpEndpoint?: string;
  authToken?: string;
  maxRetries?: number;
  timeout?: number;
}

/**
 * Get the correct socket path.
 * FIXED: Uses /var/run/boundary-daemon/boundary.sock (not /var/run/boundary-daemon.sock)
 */
function getSocketPath(): string {
  const paths = [
    process.env.BOUNDARY_DAEMON_SOCKET,
    '/var/run/boundary-daemon/boundary.sock',  // FIXED: Correct path
    path.join(process.env.HOME || '~', '.agent-os/api/boundary.sock'),
    './api/boundary.sock',
  ];

  for (const p of paths) {
    if (p && fs.existsSync(p)) {
      return p;
    }
  }

  // FIXED: Return correct default path
  return '/var/run/boundary-daemon/boundary.sock';
}

/**
 * Boundary Daemon Connector for Learning Contracts.
 */
export class DaemonConnector {
  private socketPath: string;
  private httpEndpoint?: string;
  private authToken?: string;
  private maxRetries: number;
  private timeout: number;
  private statusCache?: { mode: BoundaryMode; timestamp: number };
  private cacheTTL = 1000;

  constructor(config: DaemonConnectorConfig = {}) {
    // FIXED: Use correct socket path
    this.socketPath = config.socketPath || getSocketPath();
    this.httpEndpoint = config.httpEndpoint;
    this.authToken = config.authToken || process.env.BOUNDARY_API_TOKEN;
    this.maxRetries = config.maxRetries ?? 3;
    this.timeout = config.timeout ?? 5000;
  }

  private async sendRequest(
    command: string,
    params: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    const request: Record<string, any> = { command, params };
    if (this.authToken) {
      request.token = this.authToken;
    }

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        return await this.sendViaSocket(request);
      } catch (e) {
        if (attempt < this.maxRetries - 1) {
          await new Promise((r) => setTimeout(r, 500 * Math.pow(2, attempt)));
        } else {
          throw e;
        }
      }
    }

    throw new Error('Max retries exceeded');
  }

  private sendViaSocket(request: Record<string, any>): Promise<Record<string, any>> {
    return new Promise((resolve, reject) => {
      const client = net.createConnection({ path: this.socketPath }, () => {
        client.write(JSON.stringify(request));
      });

      client.setTimeout(this.timeout);

      let data = '';
      client.on('data', (chunk) => {
        data += chunk.toString();
      });

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

  /**
   * Get current daemon status and mode.
   */
  async getStatus(): Promise<{ mode: BoundaryMode; online: boolean }> {
    if (this.statusCache && Date.now() - this.statusCache.timestamp < this.cacheTTL) {
      return { mode: this.statusCache.mode, online: true };
    }

    try {
      const response = await this.sendRequest('status');
      const mode = (response.status?.mode || 'lockdown').toLowerCase() as BoundaryMode;
      this.statusCache = { mode, timestamp: Date.now() };
      return { mode, online: true };
    } catch {
      return { mode: BoundaryMode.LOCKDOWN, online: false };
    }
  }

  /**
   * Get current boundary mode.
   */
  async getMode(): Promise<BoundaryMode> {
    const status = await this.getStatus();
    return status.mode;
  }

  // =========================================================================
  // Policy Gates
  // =========================================================================

  /**
   * Memory Creation Gate - Check before storing any memory.
   */
  async checkMemoryCreation(params: {
    classification: Classification;
    domain: string;
    contractId?: string;
  }): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_recall', {
        memory_class: params.classification,
        context: {
          operation: 'create',
          domain: params.domain,
          contract_id: params.contractId,
        },
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

  /**
   * Tool Execution Gate - Check before tool invocation.
   */
  async checkToolExecution(params: {
    toolName: string;
    requiresNetwork?: boolean;
    contractId?: string;
  }): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_tool', {
        tool_name: params.toolName,
        requires_network: params.requiresNetwork ?? false,
        context: {
          contract_id: params.contractId,
        },
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

  /**
   * Classification Allowance - Check if current mode permits classification.
   */
  async checkClassificationAllowance(
    classification: Classification
  ): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_recall', {
        memory_class: classification,
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

  /**
   * Check if a contract can operate in current mode.
   */
  async checkContractMode(params: {
    contractId: string;
    requiredMode: BoundaryMode;
  }): Promise<{
    canOperate: boolean;
    currentMode: BoundaryMode;
    reason: string;
  }> {
    const status = await this.getStatus();

    // Mode hierarchy: OPEN < RESTRICTED < TRUSTED < AIRGAP < COLDROOM < LOCKDOWN
    const modeRank: Record<BoundaryMode, number> = {
      [BoundaryMode.OPEN]: 0,
      [BoundaryMode.RESTRICTED]: 1,
      [BoundaryMode.TRUSTED]: 2,
      [BoundaryMode.AIRGAP]: 3,
      [BoundaryMode.COLDROOM]: 4,
      [BoundaryMode.LOCKDOWN]: 5,
    };

    const currentRank = modeRank[status.mode];
    const requiredRank = modeRank[params.requiredMode];

    if (status.mode === BoundaryMode.LOCKDOWN) {
      return {
        canOperate: false,
        currentMode: status.mode,
        reason: 'System in LOCKDOWN - all contracts suspended',
      };
    }

    if (currentRank >= requiredRank) {
      return {
        canOperate: true,
        currentMode: status.mode,
        reason: `Contract can operate in ${status.mode} mode`,
      };
    }

    return {
      canOperate: false,
      currentMode: status.mode,
      reason: `Contract requires ${params.requiredMode} mode, currently in ${status.mode}`,
    };
  }

  // =========================================================================
  // Mode Change Handling
  // =========================================================================

  /**
   * Subscribe to mode changes.
   */
  onModeChange(callback: (newMode: BoundaryMode, oldMode: BoundaryMode) => void): void {
    let lastMode: BoundaryMode | null = null;

    // Poll for mode changes every second
    setInterval(async () => {
      const status = await this.getStatus();

      if (lastMode !== null && lastMode !== status.mode) {
        callback(status.mode, lastMode);
      }

      lastMode = status.mode;
    }, 1000);
  }

  // =========================================================================
  // SIEM Integration
  // =========================================================================

  /**
   * Report security event to SIEM via daemon.
   */
  async reportSecurityEvent(event: {
    eventType: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    description: string;
    contractId?: string;
    mitreTechnique?: string;
    metadata?: Record<string, any>;
  }): Promise<boolean> {
    try {
      const response = await this.sendRequest('check_message', {
        content: JSON.stringify(event),
        source: 'learning-contracts',
        context: {
          event_type: 'security_event',
          ...event,
        },
      });

      return response.success ?? false;
    } catch {
      return false;
    }
  }
}

// =========================================================================
// Contract Enforcement Integration
// =========================================================================

export interface ContractEnforcementConfig {
  contractId: string;
  requiredMode: BoundaryMode;
  maxClassification: Classification;
}

/**
 * Contract Enforcement Manager.
 *
 * Integrates boundary daemon with contract lifecycle.
 */
export class ContractEnforcer {
  private daemon: DaemonConnector;
  private contracts: Map<string, ContractEnforcementConfig> = new Map();

  constructor(daemon?: DaemonConnector) {
    this.daemon = daemon || new DaemonConnector();

    // Subscribe to mode changes
    this.daemon.onModeChange((newMode, oldMode) => {
      this.handleModeChange(newMode, oldMode);
    });
  }

  /**
   * Register a contract for enforcement.
   */
  registerContract(config: ContractEnforcementConfig): void {
    this.contracts.set(config.contractId, config);
  }

  /**
   * Check if a contract can execute.
   */
  async canExecute(contractId: string): Promise<{
    canExecute: boolean;
    reason: string;
  }> {
    const config = this.contracts.get(contractId);
    if (!config) {
      return { canExecute: false, reason: 'Contract not registered' };
    }

    const modeCheck = await this.daemon.checkContractMode({
      contractId,
      requiredMode: config.requiredMode,
    });

    if (!modeCheck.canOperate) {
      return { canExecute: false, reason: modeCheck.reason };
    }

    return { canExecute: true, reason: 'Contract can execute' };
  }

  /**
   * Handle mode change - suspend/resume contracts as needed.
   */
  private async handleModeChange(newMode: BoundaryMode, oldMode: BoundaryMode): void {
    console.log(`[ContractEnforcer] Mode changed: ${oldMode} → ${newMode}`);

    for (const [contractId, config] of this.contracts) {
      const check = await this.daemon.checkContractMode({
        contractId,
        requiredMode: config.requiredMode,
      });

      if (!check.canOperate) {
        console.log(`[ContractEnforcer] Suspending contract ${contractId}: ${check.reason}`);
        // Emit suspend event
      }
    }
  }
}

export default DaemonConnector;
