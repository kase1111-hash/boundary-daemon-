/**
 * Boundary Client for Agent-OS
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

export interface AgentOSCheckResult extends PolicyDecision {
  senderAgent: string;
  recipientAgent: string;
  messageType: string;
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
  private maxRetries: number;
  private timeout: number;

  constructor(config: {
    socketPath?: string;
    token?: string;
    maxRetries?: number;
    timeout?: number;
  } = {}) {
    this.socketPath = config.socketPath || getSocketPath();
    this.token = config.token || process.env.BOUNDARY_API_TOKEN;
    this.maxRetries = config.maxRetries ?? 3;
    this.timeout = config.timeout ?? 5000;
  }

  private async sendRequest(
    command: string,
    params: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    const request: Record<string, any> = { command, params };
    if (this.token) {
      request.token = this.token;
    }

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        return await this.sendOnce(request);
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

  private sendOnce(request: Record<string, any>): Promise<Record<string, any>> {
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

  async getStatus(): Promise<{ mode: BoundaryMode; online: boolean }> {
    try {
      const response = await this.sendRequest('status');
      return {
        mode: (response.status?.mode || 'lockdown').toLowerCase() as BoundaryMode,
        online: response.status?.online ?? false,
      };
    } catch {
      return { mode: BoundaryMode.LOCKDOWN, online: false };
    }
  }

  async getMode(): Promise<BoundaryMode> {
    const status = await this.getStatus();
    return status.mode;
  }

  async checkTool(
    toolName: string,
    options: {
      requiresNetwork?: boolean;
      requiresFilesystem?: boolean;
      requiresUsb?: boolean;
    } = {}
  ): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_tool', {
        tool_name: toolName,
        requires_network: options.requiresNetwork ?? false,
        requires_filesystem: options.requiresFilesystem ?? false,
        requires_usb: options.requiresUsb ?? false,
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

  async checkAgentMessage(params: {
    senderAgent: string;
    recipientAgent: string;
    content: string;
    messageType?: string;
    authorityLevel?: number;
    requiresConsent?: boolean;
    metadata?: Record<string, any>;
  }): Promise<AgentOSCheckResult> {
    try {
      const response = await this.sendRequest('check_agentos', {
        sender_agent: params.senderAgent,
        recipient_agent: params.recipientAgent,
        content: params.content,
        message_type: params.messageType || 'request',
        authority_level: params.authorityLevel ?? 0,
        requires_consent: params.requiresConsent ?? false,
        metadata: params.metadata,
      });

      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
        senderAgent: params.senderAgent,
        recipientAgent: params.recipientAgent,
        messageType: params.messageType || 'request',
      };
    } catch {
      return {
        permitted: false,
        reason: 'Boundary daemon unavailable - fail closed',
        senderAgent: params.senderAgent,
        recipientAgent: params.recipientAgent,
        messageType: params.messageType || 'request',
      };
    }
  }

  async checkMessage(
    content: string,
    source = 'agent-os',
    context?: Record<string, any>
  ): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_message', {
        content,
        source,
        context,
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

  async checkRecall(memoryClass: number): Promise<PolicyDecision> {
    try {
      const response = await this.sendRequest('check_recall', {
        memory_class: memoryClass,
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

export default BoundaryClient;
