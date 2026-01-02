/**
 * Agent Smith (Guardian Agent) Integration
 *
 * This module integrates the boundary daemon with Agent-OS's Smith agent,
 * providing security validation, constitutional enforcement, and attack detection.
 */

import { BoundaryClient, BoundaryMode, PolicyDecision } from './client';
import { AgentMessageGate, ToolGate, ConstitutionGate } from './gates';

export interface SecurityValidationResult {
  valid: boolean;
  violations: string[];
  recommendations: string[];
  mode: BoundaryMode;
}

export interface AttackDetectionResult {
  detected: boolean;
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  indicators: string[];
  mitigations: string[];
}

/**
 * Smith Guardian Agent Boundary Integration.
 *
 * This class provides the security layer that Smith uses to:
 * - Validate operations against boundary policies
 * - Detect and respond to attacks
 * - Enforce constitutional governance
 */
export class SmithBoundaryIntegration {
  private client: BoundaryClient;
  private toolGate: ToolGate;
  private messageGate: AgentMessageGate;
  private constitutionGate: ConstitutionGate;

  constructor() {
    this.client = new BoundaryClient();
    this.toolGate = new ToolGate(this.client);
    this.messageGate = new AgentMessageGate(this.client);
    this.constitutionGate = new ConstitutionGate(this.client);
  }

  /**
   * Validate an operation for security compliance.
   */
  async validateOperation(params: {
    operation: string;
    agent: string;
    target?: string;
    requiresNetwork?: boolean;
    requiresFilesystem?: boolean;
    requiresUsb?: boolean;
    memoryClass?: number;
  }): Promise<SecurityValidationResult> {
    const violations: string[] = [];
    const recommendations: string[] = [];

    const mode = await this.client.getMode();

    // Check tool permission
    const toolDecision = await this.client.checkTool(params.operation, {
      requiresNetwork: params.requiresNetwork,
      requiresFilesystem: params.requiresFilesystem,
      requiresUsb: params.requiresUsb,
    });

    if (!toolDecision.permitted) {
      violations.push(`Tool denied: ${toolDecision.reason}`);
    }

    // Check memory permission if applicable
    if (params.memoryClass !== undefined) {
      const recallDecision = await this.client.checkRecall(params.memoryClass);
      if (!recallDecision.permitted) {
        violations.push(`Memory access denied: ${recallDecision.reason}`);
      }
    }

    // Mode-specific recommendations
    if (mode === BoundaryMode.OPEN && params.requiresNetwork) {
      recommendations.push(
        'Consider RESTRICTED mode for network operations'
      );
    }

    if (params.memoryClass && params.memoryClass >= 3) {
      if (mode === BoundaryMode.OPEN || mode === BoundaryMode.RESTRICTED) {
        recommendations.push(
          `High-classification memory (${params.memoryClass}) accessed in ${mode} mode`
        );
      }
    }

    return {
      valid: violations.length === 0,
      violations,
      recommendations,
      mode,
    };
  }

  /**
   * Check for attack indicators in an operation.
   */
  async detectAttack(params: {
    content: string;
    source: string;
    agent?: string;
    context?: Record<string, any>;
  }): Promise<AttackDetectionResult> {
    const indicators: string[] = [];
    const mitigations: string[] = [];

    // Check message content with boundary daemon
    const decision = await this.client.checkMessage(
      params.content,
      params.source,
      {
        ...params.context,
        check_type: 'attack_detection',
        agent: params.agent,
      }
    );

    if (!decision.permitted) {
      indicators.push(decision.reason);
    }

    // Determine threat level based on indicators
    let threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical' = 'none';

    if (indicators.length > 0) {
      // Check for specific patterns
      const content = params.content.toLowerCase();

      if (
        content.includes('ignore previous') ||
        content.includes('ignore all') ||
        content.includes('you are now')
      ) {
        threatLevel = 'high';
        indicators.push('Potential prompt injection detected');
        mitigations.push('Reject request', 'Log for review');
      } else if (
        content.includes('system:') ||
        content.includes('developer mode')
      ) {
        threatLevel = 'medium';
        indicators.push('Authority escalation attempt');
        mitigations.push('Verify authority level', 'Require confirmation');
      } else {
        threatLevel = 'low';
        mitigations.push('Monitor for patterns');
      }
    }

    return {
      detected: indicators.length > 0,
      threatLevel,
      indicators,
      mitigations,
    };
  }

  /**
   * Enforce constitutional limits on an action.
   */
  async enforceConstitution(params: {
    action: string;
    agent: string;
    target?: string;
    authority: number;
    context?: Record<string, any>;
  }): Promise<{
    permitted: boolean;
    violations: string[];
    requiresCeremony: boolean;
  }> {
    const violations: string[] = [];

    // Check constitutional compliance
    const decision = await this.constitutionGate.checkConstitutionalCompliance(
      params.action,
      {
        agent: params.agent,
        target: params.target,
        authority: params.authority,
        ...params.context,
      }
    );

    if (!decision.permitted) {
      violations.push(`Constitutional violation: ${decision.reason}`);
    }

    // Check if action requires ceremony (high authority)
    const requiresCeremony = params.authority >= 4;

    if (requiresCeremony) {
      violations.push('Action requires human ceremony approval');
    }

    return {
      permitted: violations.length === 0 || (violations.length === 1 && requiresCeremony),
      violations,
      requiresCeremony,
    };
  }

  /**
   * Get recommended security mode for current context.
   */
  async getRecommendedMode(context: {
    sensitiveData: boolean;
    networkRequired: boolean;
    highClassification: boolean;
  }): Promise<{
    recommended: BoundaryMode;
    current: BoundaryMode;
    reason: string;
  }> {
    const current = await this.client.getMode();
    let recommended = current;
    let reason = 'Current mode is appropriate';

    if (context.highClassification) {
      if (current === BoundaryMode.OPEN || current === BoundaryMode.RESTRICTED) {
        recommended = BoundaryMode.TRUSTED;
        reason = 'High-classification data requires TRUSTED mode or higher';
      }
    }

    if (context.sensitiveData && !context.networkRequired) {
      if (current === BoundaryMode.OPEN) {
        recommended = BoundaryMode.AIRGAP;
        reason = 'Sensitive data without network requirement suggests AIRGAP';
      }
    }

    return { recommended, current, reason };
  }
}

/**
 * Create a security-wrapped agent executor.
 */
export function createSecureAgentExecutor(
  agentName: string,
  executor: (action: string, params: any) => Promise<any>
): (action: string, params: any) => Promise<any> {
  const smith = new SmithBoundaryIntegration();

  return async (action: string, params: any) => {
    // Validate operation
    const validation = await smith.validateOperation({
      operation: action,
      agent: agentName,
      requiresNetwork: params.network,
      requiresFilesystem: params.filesystem,
      memoryClass: params.memoryClass,
    });

    if (!validation.valid) {
      throw new Error(
        `Security validation failed: ${validation.violations.join(', ')}`
      );
    }

    // Check for attacks if there's content
    if (params.content) {
      const attackCheck = await smith.detectAttack({
        content: params.content,
        source: agentName,
        agent: agentName,
      });

      if (attackCheck.threatLevel === 'high' || attackCheck.threatLevel === 'critical') {
        throw new Error(
          `Attack detected: ${attackCheck.indicators.join(', ')}`
        );
      }
    }

    // Execute the action
    return executor(action, params);
  };
}
