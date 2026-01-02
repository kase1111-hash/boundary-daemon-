/**
 * Agent-OS Boundary Gates
 *
 * Gates provide structured access control for Agent-OS operations.
 */

import { BoundaryClient, PolicyDecision, BoundaryMode } from './client';

export class ToolGate {
  private client: BoundaryClient;
  private lastDecision?: PolicyDecision;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): PolicyDecision | undefined {
    return this.lastDecision;
  }

  async canExecute(
    toolName: string,
    options: {
      network?: boolean;
      filesystem?: boolean;
      usb?: boolean;
    } = {}
  ): Promise<boolean> {
    const decision = await this.client.checkTool(toolName, {
      requiresNetwork: options.network,
      requiresFilesystem: options.filesystem,
      requiresUsb: options.usb,
    });

    this.lastDecision = decision;
    return decision.permitted;
  }

  async requireExecution(
    toolName: string,
    options: {
      network?: boolean;
      filesystem?: boolean;
      usb?: boolean;
    } = {}
  ): Promise<void> {
    const canExecute = await this.canExecute(toolName, options);
    if (!canExecute) {
      throw new Error(
        `Tool '${toolName}' execution denied: ${this.lastDecision?.reason}`
      );
    }
  }

  async executeIfPermitted<T>(
    toolName: string,
    executeFn: () => Promise<T>,
    options: {
      network?: boolean;
      filesystem?: boolean;
      usb?: boolean;
      default?: T;
    } = {}
  ): Promise<T | undefined> {
    const canExecute = await this.canExecute(toolName, {
      network: options.network,
      filesystem: options.filesystem,
      usb: options.usb,
    });

    if (canExecute) {
      return executeFn();
    }

    return options.default;
  }
}

export class AgentMessageGate {
  private client: BoundaryClient;
  private lastDecision?: PolicyDecision;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): PolicyDecision | undefined {
    return this.lastDecision;
  }

  async canSend(params: {
    sender: string;
    recipient: string;
    content: string;
    type?: string;
    authorityLevel?: number;
  }): Promise<boolean> {
    const decision = await this.client.checkAgentMessage({
      senderAgent: params.sender,
      recipientAgent: params.recipient,
      content: params.content,
      messageType: params.type,
      authorityLevel: params.authorityLevel,
    });

    this.lastDecision = decision;
    return decision.permitted;
  }

  async requireSend(params: {
    sender: string;
    recipient: string;
    content: string;
    type?: string;
    authorityLevel?: number;
  }): Promise<void> {
    const canSend = await this.canSend(params);
    if (!canSend) {
      throw new Error(
        `Message from '${params.sender}' to '${params.recipient}' denied: ${this.lastDecision?.reason}`
      );
    }
  }
}

export class ModelGate {
  private client: BoundaryClient;
  private lastDecision?: PolicyDecision;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  getLastDecision(): PolicyDecision | undefined {
    return this.lastDecision;
  }

  async canCallModel(modelName: string): Promise<boolean> {
    // External model calls require network
    const decision = await this.client.checkTool(`model:${modelName}`, {
      requiresNetwork: true,
    });

    this.lastDecision = decision;
    return decision.permitted;
  }

  async callModelIfPermitted<T>(
    modelName: string,
    callFn: () => Promise<T>,
    localFallback?: () => Promise<T>
  ): Promise<T | undefined> {
    const canCall = await this.canCallModel(modelName);

    if (canCall) {
      return callFn();
    }

    if (localFallback) {
      console.log(`External model '${modelName}' denied, using local fallback`);
      return localFallback();
    }

    return undefined;
  }
}

export class ConstitutionGate {
  private client: BoundaryClient;

  constructor(client?: BoundaryClient) {
    this.client = client || new BoundaryClient();
  }

  async checkConstitutionalCompliance(
    action: string,
    context: Record<string, any>
  ): Promise<PolicyDecision> {
    return this.client.checkMessage(
      `CONSTITUTIONAL_CHECK:${action}`,
      'agent-os-constitution',
      context
    );
  }

  async requireConstitutionalCompliance(
    action: string,
    context: Record<string, any>
  ): Promise<void> {
    const decision = await this.checkConstitutionalCompliance(action, context);
    if (!decision.permitted) {
      throw new Error(
        `Constitutional violation for '${action}': ${decision.reason}`
      );
    }
  }
}

/**
 * Main integration class combining all gates.
 */
export class AgentOSBoundaryIntegration {
  public readonly toolGate: ToolGate;
  public readonly messageGate: AgentMessageGate;
  public readonly modelGate: ModelGate;
  public readonly constitutionGate: ConstitutionGate;

  private client: BoundaryClient;

  constructor() {
    this.client = new BoundaryClient();
    this.toolGate = new ToolGate(this.client);
    this.messageGate = new AgentMessageGate(this.client);
    this.modelGate = new ModelGate(this.client);
    this.constitutionGate = new ConstitutionGate(this.client);
  }

  async getMode(): Promise<BoundaryMode> {
    return this.client.getMode();
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.client.getStatus();
      return true;
    } catch {
      return false;
    }
  }

  async isSecureMode(): Promise<boolean> {
    const mode = await this.getMode();
    return [
      BoundaryMode.TRUSTED,
      BoundaryMode.AIRGAP,
      BoundaryMode.COLDROOM,
      BoundaryMode.LOCKDOWN,
    ].includes(mode);
  }
}
