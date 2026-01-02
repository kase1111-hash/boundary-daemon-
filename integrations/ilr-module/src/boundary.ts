/**
 * ILR Module Boundary Integration
 *
 * Provides boundary daemon integration for the IP & Licensing Reconciliation
 * Module (ILRM), which handles dispute resolution and licensing.
 *
 * Key integration points:
 * - Dispute content validation
 * - Licensing agreement access control
 * - Resolution workflow enforcement
 * - Economic transaction authorization
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

export enum DisputeClass {
  PUBLIC = 0,
  INTERNAL = 1,
  CONFIDENTIAL = 2,
  SENSITIVE = 3,
  RESTRICTED = 4,
  PRIVILEGED = 5,
}

export interface PolicyDecision {
  permitted: boolean;
  reason: string;
  mode?: BoundaryMode;
}

export interface DisputeValidationResult extends PolicyDecision {
  requiredMode?: BoundaryMode;
  requiresMediation?: boolean;
  economicLimit?: number;
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

  async checkDisputeContent(
    content: string,
    disputeClass: DisputeClass,
    parties: string[],
  ): Promise<DisputeValidationResult> {
    try {
      const response = await this.sendRequest('check_message', {
        content,
        source: 'ilr-module',
        context: {
          type: 'dispute',
          dispute_class: disputeClass,
          parties,
        },
      });

      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
        requiredMode: response.result?.required_mode,
        requiresMediation: response.result?.requires_mediation,
        economicLimit: response.result?.economic_limit,
      };
    } catch {
      return {
        permitted: false,
        reason: 'Boundary daemon unavailable - fail closed',
      };
    }
  }

  async checkLicenseAccess(
    licenseClass: number,
    licenseId?: string,
  ): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_recall', {
        memory_class: licenseClass,
        memory_id: licenseId,
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

  async checkResolutionAction(
    actionType: string,
    requiresNetwork: boolean = false,
  ): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_tool', {
        tool_name: `ilr:${actionType}`,
        requires_network: requiresNetwork,
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
 * Dispute Gate.
 *
 * Controls dispute-related operations.
 */
export class DisputeGate {
  private client: BoundaryClient;
  private lastDecision?: DisputeValidationResult;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): DisputeValidationResult | undefined {
    return this.lastDecision;
  }

  async canFileDispute(
    content: string,
    disputeClass: DisputeClass,
    parties: string[],
  ): Promise<boolean> {
    this.lastDecision = await this.client.checkDisputeContent(content, disputeClass, parties);
    return this.lastDecision.permitted;
  }

  async requireDisputePermission(
    content: string,
    disputeClass: DisputeClass,
    parties: string[],
  ): Promise<void> {
    const canFile = await this.canFileDispute(content, disputeClass, parties);
    if (!canFile) {
      throw new Error(`Dispute filing denied: ${this.lastDecision?.reason}`);
    }
  }
}

/**
 * License Gate.
 *
 * Controls access to licensing agreements.
 */
export class LicenseGate {
  private client: BoundaryClient;
  private lastDecision?: PolicyDecision;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): PolicyDecision | undefined {
    return this.lastDecision;
  }

  async canAccessLicense(licenseClass: number, licenseId?: string): Promise<boolean> {
    this.lastDecision = await this.client.checkLicenseAccess(licenseClass, licenseId);
    return this.lastDecision.permitted;
  }

  async requireLicenseAccess(licenseClass: number, licenseId?: string): Promise<void> {
    const canAccess = await this.canAccessLicense(licenseClass, licenseId);
    if (!canAccess) {
      throw new Error(`License access denied: ${this.lastDecision?.reason}`);
    }
  }
}

/**
 * Resolution Gate.
 *
 * Controls resolution workflow actions.
 */
export class ResolutionGate {
  private client: BoundaryClient;
  private lastDecision?: PolicyDecision;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): PolicyDecision | undefined {
    return this.lastDecision;
  }

  async canPerformAction(actionType: string, requiresNetwork = false): Promise<boolean> {
    this.lastDecision = await this.client.checkResolutionAction(actionType, requiresNetwork);
    return this.lastDecision.permitted;
  }

  async requireActionPermission(actionType: string, requiresNetwork = false): Promise<void> {
    const canPerform = await this.canPerformAction(actionType, requiresNetwork);
    if (!canPerform) {
      throw new Error(`Resolution action '${actionType}' denied: ${this.lastDecision?.reason}`);
    }
  }
}

/**
 * Main integration class for ILR Module.
 */
export class ILRBoundaryIntegration {
  public readonly disputeGate: DisputeGate;
  public readonly licenseGate: LicenseGate;
  public readonly resolutionGate: ResolutionGate;
  private client: BoundaryClient;

  constructor() {
    this.client = new BoundaryClient();
    this.disputeGate = new DisputeGate(this.client);
    this.licenseGate = new LicenseGate(this.client);
    this.resolutionGate = new ResolutionGate(this.client);
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

  /**
   * Check if dispute resolution workflow can proceed.
   */
  async canResolveDispute(params: {
    disputeContent: string;
    disputeClass: DisputeClass;
    parties: string[];
    requiresPayment: boolean;
  }): Promise<{ canProceed: boolean; reason: string }> {
    // Check dispute content
    const disputeCheck = await this.disputeGate.canFileDispute(
      params.disputeContent,
      params.disputeClass,
      params.parties
    );

    if (!disputeCheck) {
      return {
        canProceed: false,
        reason: this.disputeGate.getLastDecision()?.reason || 'Dispute check failed',
      };
    }

    // Check resolution action
    const actionCheck = await this.resolutionGate.canPerformAction(
      'resolve',
      params.requiresPayment
    );

    if (!actionCheck) {
      return {
        canProceed: false,
        reason: this.resolutionGate.getLastDecision()?.reason || 'Resolution check failed',
      };
    }

    return { canProceed: true, reason: 'Resolution workflow permitted' };
  }

  /**
   * Execute resolution with boundary enforcement.
   */
  async executeWithBoundary<T>(
    actionType: string,
    executeFn: () => Promise<T>,
    requiresNetwork = false
  ): Promise<T | undefined> {
    const canPerform = await this.resolutionGate.canPerformAction(actionType, requiresNetwork);

    if (!canPerform) {
      console.warn(`Action '${actionType}' denied: ${this.resolutionGate.getLastDecision()?.reason}`);
      return undefined;
    }

    return executeFn();
  }
}

export default ILRBoundaryIntegration;
