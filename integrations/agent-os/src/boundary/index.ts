/**
 * Agent-OS Boundary Daemon Integration
 *
 * This module provides comprehensive boundary enforcement for Agent-OS.
 * All tool executions, agent communications, and model calls MUST pass
 * through these gates.
 *
 * INTEGRATION REQUIREMENT:
 * Per INTEGRATION.md, Agent-OS MUST call boundary daemon before:
 * - Any tool execution
 * - Inter-agent communications
 * - External model API calls
 *
 * Usage:
 *   import { ToolGate, AgentMessageGate, boundaryProtected } from './boundary';
 *
 *   // Before tool execution
 *   const gate = new ToolGate();
 *   if (await gate.canExecute('wget', { network: true })) {
 *     await executeTool('wget', args);
 *   }
 *
 *   // Or use decorator
 *   class MyTool {
 *     @boundaryProtected({ requiresNetwork: true })
 *     async run() { ... }
 *   }
 */

export * from './client';
export * from './gates';
export * from './decorators';
export * from './smith-integration';
