/**
 * Shared Boundary Daemon Client for TypeScript Integrations
 *
 * This is the base client that all TypeScript integrations should use.
 * Provides fail-closed semantics, automatic retry, and token management.
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

export enum MemoryClass {
  PUBLIC = 0,
  INTERNAL = 1,
  CONFIDENTIAL = 2,
  SECRET = 3,
  TOP_SECRET = 4,
  CROWN_JEWEL = 5,
}

export interface BoundaryStatus {
  mode: BoundaryMode;
  online: boolean;
  networkState: string;
  hardwareTrust: string;
  lockdownActive: boolean;
  tripwireCount: number;
  uptimeSeconds: number;
}

export interface PolicyDecision {
  permitted: boolean;
  reason: string;
  mode?: BoundaryMode;
  requiresCeremony?: boolean;
}

export class BoundaryDaemonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BoundaryDaemonError';
  }
}

export class DaemonUnavailableError extends BoundaryDaemonError {
  constructor(message: string) {
    super(message);
    this.name = 'DaemonUnavailableError';
  }
}

export class AuthenticationError extends BoundaryDaemonError {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class PolicyDeniedError extends BoundaryDaemonError {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyDeniedError';
  }
}

export interface BoundaryClientConfig {
  socketPath?: string;
  token?: string;
  tokenFile?: string;
  maxRetries?: number;
  retryDelay?: number;
  timeout?: number;
  failClosed?: boolean;
}

/**
 * Get the boundary daemon socket path.
 */
function getSocketPath(): string {
  // Environment variable takes precedence
  const envPath = process.env.BOUNDARY_DAEMON_SOCKET;
  if (envPath && fs.existsSync(envPath)) {
    return envPath;
  }

  // Production path
  const prodPath = '/var/run/boundary-daemon/boundary.sock';
  if (fs.existsSync(prodPath)) {
    return prodPath;
  }

  // User mode path
  const userPath = path.join(
    process.env.HOME || '~',
    '.agent-os/api/boundary.sock'
  );
  if (fs.existsSync(userPath)) {
    return userPath;
  }

  // Development path
  const devPath = './api/boundary.sock';
  if (fs.existsSync(devPath)) {
    return devPath;
  }

  return prodPath;
}

/**
 * Universal Boundary Daemon Client for TypeScript.
 */
export class BoundaryClient {
  private socketPath: string;
  private token?: string;
  private maxRetries: number;
  private retryDelay: number;
  private timeout: number;
  private failClosed: boolean;
  private statusCache?: { status: BoundaryStatus; timestamp: number };
  private cacheTTL = 1000; // 1 second

  constructor(config: BoundaryClientConfig = {}) {
    this.socketPath = config.socketPath || getSocketPath();
    this.token = this.resolveToken(config.token, config.tokenFile);
    this.maxRetries = config.maxRetries ?? 3;
    this.retryDelay = config.retryDelay ?? 500;
    this.timeout = config.timeout ?? 5000;
    this.failClosed = config.failClosed ?? true;
  }

  private resolveToken(
    token?: string,
    tokenFile?: string
  ): string | undefined {
    if (token) {
      return token.trim();
    }

    if (tokenFile) {
      try {
        const content = fs.readFileSync(tokenFile, 'utf-8');
        for (const line of content.split('\n')) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
            return trimmed;
          }
        }
      } catch (e) {
        console.warn(`Could not read token file: ${e}`);
      }
    }

    // Try environment variable
    const envToken = process.env.BOUNDARY_API_TOKEN;
    if (envToken) {
      return envToken.trim();
    }

    return undefined;
  }

  private async sendRequest(
    command: string,
    params: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    const request: Record<string, any> = { command, params };
    if (this.token) {
      request.token = this.token;
    }

    let lastError: Error | undefined;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        return await this.sendOnce(request);
      } catch (e) {
        lastError = e as Error;
        if (attempt < this.maxRetries - 1) {
          const delay = this.retryDelay * Math.pow(2, attempt);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }

    if (this.failClosed) {
      throw new DaemonUnavailableError(
        `Boundary daemon unavailable after ${this.maxRetries} attempts: ${lastError?.message}`
      );
    }
    return { success: false, error: lastError?.message };
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
        } catch (e) {
          reject(new Error(`Invalid JSON response: ${data}`));
        }
      });

      client.on('error', (err) => {
        reject(err);
      });

      client.on('timeout', () => {
        client.destroy();
        reject(new Error('Connection timeout'));
      });
    });
  }

  async getStatus(useCache = true): Promise<BoundaryStatus> {
    if (
      useCache &&
      this.statusCache &&
      Date.now() - this.statusCache.timestamp < this.cacheTTL
    ) {
      return this.statusCache.status;
    }

    try {
      const response = await this.sendRequest('status');
      if (!response.success) {
        if (this.failClosed) {
          return {
            mode: BoundaryMode.LOCKDOWN,
            online: false,
            networkState: 'unknown',
            hardwareTrust: 'low',
            lockdownActive: true,
            tripwireCount: 0,
            uptimeSeconds: 0,
          };
        }
        throw new BoundaryDaemonError(response.error || 'Unknown error');
      }

      const status: BoundaryStatus = {
        mode: (response.status?.mode || 'lockdown').toLowerCase() as BoundaryMode,
        online: response.status?.online ?? false,
        networkState: response.status?.network_state || 'unknown',
        hardwareTrust: response.status?.hardware_trust || 'low',
        lockdownActive: response.status?.lockdown_active ?? true,
        tripwireCount: response.status?.tripwire_count ?? 0,
        uptimeSeconds: response.status?.uptime_seconds ?? 0,
      };

      this.statusCache = { status, timestamp: Date.now() };
      return status;
    } catch (e) {
      if (this.failClosed) {
        return {
          mode: BoundaryMode.LOCKDOWN,
          online: false,
          networkState: 'unknown',
          hardwareTrust: 'low',
          lockdownActive: true,
          tripwireCount: 0,
          uptimeSeconds: 0,
        };
      }
      throw e;
    }
  }

  async getMode(): Promise<BoundaryMode> {
    const status = await this.getStatus();
    return status.mode;
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.getStatus(false);
      return true;
    } catch {
      return false;
    }
  }

  async checkRecall(
    memoryClass: number,
    memoryId?: string
  ): Promise<PolicyDecision> {
    const params: Record<string, any> = { memory_class: memoryClass };
    if (memoryId) {
      params.memory_id = memoryId;
    }

    try {
      const response = await this.sendRequest('check_recall', params);
      if (response.auth_error) {
        throw new AuthenticationError(response.error || 'Authentication failed');
      }
      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
      };
    } catch (e) {
      if (e instanceof DaemonUnavailableError) {
        return {
          permitted: false,
          reason: 'Boundary daemon unavailable - fail closed',
        };
      }
      throw e;
    }
  }

  async checkTool(
    toolName: string,
    options: {
      requiresNetwork?: boolean;
      requiresFilesystem?: boolean;
      requiresUsb?: boolean;
    } = {}
  ): Promise<PolicyDecision> {
    const params = {
      tool_name: toolName,
      requires_network: options.requiresNetwork ?? false,
      requires_filesystem: options.requiresFilesystem ?? false,
      requires_usb: options.requiresUsb ?? false,
    };

    try {
      const response = await this.sendRequest('check_tool', params);
      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
      };
    } catch (e) {
      if (e instanceof DaemonUnavailableError) {
        return {
          permitted: false,
          reason: 'Boundary daemon unavailable - fail closed',
        };
      }
      throw e;
    }
  }

  async checkMessage(
    content: string,
    source = 'unknown',
    context?: Record<string, any>
  ): Promise<PolicyDecision> {
    const params: Record<string, any> = { content, source };
    if (context) {
      params.context = context;
    }

    try {
      const response = await this.sendRequest('check_message', params);
      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
      };
    } catch (e) {
      if (e instanceof DaemonUnavailableError) {
        return {
          permitted: false,
          reason: 'Boundary daemon unavailable - fail closed',
        };
      }
      throw e;
    }
  }

  async checkNatLangChain(params: {
    author: string;
    intent: string;
    timestamp: string;
    signature?: string;
    previousHash?: string;
    metadata?: Record<string, any>;
  }): Promise<PolicyDecision> {
    const requestParams: Record<string, any> = {
      author: params.author,
      intent: params.intent,
      timestamp: params.timestamp,
    };
    if (params.signature) requestParams.signature = params.signature;
    if (params.previousHash) requestParams.previous_hash = params.previousHash;
    if (params.metadata) requestParams.metadata = params.metadata;

    try {
      const response = await this.sendRequest('check_natlangchain', requestParams);
      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
      };
    } catch (e) {
      if (e instanceof DaemonUnavailableError) {
        return {
          permitted: false,
          reason: 'Boundary daemon unavailable - fail closed',
        };
      }
      throw e;
    }
  }

  async checkAgentOS(params: {
    senderAgent: string;
    recipientAgent: string;
    content: string;
    messageType?: string;
    authorityLevel?: number;
    timestamp?: string;
    requiresConsent?: boolean;
    metadata?: Record<string, any>;
  }): Promise<PolicyDecision> {
    const requestParams: Record<string, any> = {
      sender_agent: params.senderAgent,
      recipient_agent: params.recipientAgent,
      content: params.content,
      message_type: params.messageType || 'request',
      authority_level: params.authorityLevel ?? 0,
      requires_consent: params.requiresConsent ?? false,
    };
    if (params.timestamp) requestParams.timestamp = params.timestamp;
    if (params.metadata) requestParams.metadata = params.metadata;

    try {
      const response = await this.sendRequest('check_agentos', requestParams);
      return {
        permitted: response.permitted ?? false,
        reason: response.reason || 'Unknown',
      };
    } catch (e) {
      if (e instanceof DaemonUnavailableError) {
        return {
          permitted: false,
          reason: 'Boundary daemon unavailable - fail closed',
        };
      }
      throw e;
    }
  }

  async setMode(
    mode: BoundaryMode,
    operator = 'human',
    reason = ''
  ): Promise<{ success: boolean; message: string }> {
    const response = await this.sendRequest('set_mode', {
      mode,
      operator,
      reason,
    });
    return {
      success: response.success ?? false,
      message: response.message || response.error || '',
    };
  }

  async verifyLog(): Promise<{ valid: boolean; error?: string }> {
    const response = await this.sendRequest('verify_log');
    return {
      valid: response.valid ?? false,
      error: response.error,
    };
  }
}

/**
 * Decorator for boundary-protected methods.
 */
export function boundaryProtected(options: {
  requiresNetwork?: boolean;
  requiresFilesystem?: boolean;
  requiresUsb?: boolean;
  memoryClass?: number;
} = {}) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const client = new BoundaryClient();

      // Check tool permission
      const toolDecision = await client.checkTool(propertyKey, {
        requiresNetwork: options.requiresNetwork,
        requiresFilesystem: options.requiresFilesystem,
        requiresUsb: options.requiresUsb,
      });

      if (!toolDecision.permitted) {
        throw new PolicyDeniedError(
          `Tool '${propertyKey}' denied: ${toolDecision.reason}`
        );
      }

      // Check memory permission if specified
      if (options.memoryClass !== undefined) {
        const recallDecision = await client.checkRecall(options.memoryClass);
        if (!recallDecision.permitted) {
          throw new PolicyDeniedError(
            `Memory access denied: ${recallDecision.reason}`
          );
        }
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

/**
 * Higher-order function for boundary protection.
 */
export function withBoundaryCheck<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  options: {
    toolName?: string;
    requiresNetwork?: boolean;
    requiresFilesystem?: boolean;
    requiresUsb?: boolean;
    memoryClass?: number;
  } = {}
): T {
  const wrapped = async (...args: Parameters<T>): Promise<ReturnType<T>> => {
    const client = new BoundaryClient();
    const toolName = options.toolName || fn.name || 'anonymous';

    const toolDecision = await client.checkTool(toolName, {
      requiresNetwork: options.requiresNetwork,
      requiresFilesystem: options.requiresFilesystem,
      requiresUsb: options.requiresUsb,
    });

    if (!toolDecision.permitted) {
      throw new PolicyDeniedError(
        `Operation '${toolName}' denied: ${toolDecision.reason}`
      );
    }

    if (options.memoryClass !== undefined) {
      const recallDecision = await client.checkRecall(options.memoryClass);
      if (!recallDecision.permitted) {
        throw new PolicyDeniedError(
          `Memory access denied: ${recallDecision.reason}`
        );
      }
    }

    return fn(...args);
  };

  return wrapped as T;
}

export default BoundaryClient;
