/**
 * Agent-OS Boundary Decorators
 */

import { BoundaryClient, PolicyDecision } from './client';
import { ToolGate } from './gates';

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
      const decision = await client.checkTool(propertyKey, {
        requiresNetwork: options.requiresNetwork,
        requiresFilesystem: options.requiresFilesystem,
        requiresUsb: options.requiresUsb,
      });

      if (!decision.permitted) {
        throw new Error(`Operation '${propertyKey}' denied: ${decision.reason}`);
      }

      // Check memory permission if specified
      if (options.memoryClass !== undefined) {
        const recallDecision = await client.checkRecall(options.memoryClass);
        if (!recallDecision.permitted) {
          throw new Error(`Memory access denied: ${recallDecision.reason}`);
        }
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

/**
 * Decorator for network-requiring operations.
 */
export function requiresNetwork() {
  return boundaryProtected({ requiresNetwork: true });
}

/**
 * Decorator for filesystem-requiring operations.
 */
export function requiresFilesystem() {
  return boundaryProtected({ requiresFilesystem: true });
}

/**
 * Decorator for USB-requiring operations.
 */
export function requiresUsb() {
  return boundaryProtected({ requiresUsb: true });
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
  } = {}
): T {
  const wrapped = async (...args: Parameters<T>): Promise<ReturnType<T>> => {
    const client = new BoundaryClient();
    const toolName = options.toolName || fn.name || 'anonymous';

    const decision = await client.checkTool(toolName, {
      requiresNetwork: options.requiresNetwork,
      requiresFilesystem: options.requiresFilesystem,
      requiresUsb: options.requiresUsb,
    });

    if (!decision.permitted) {
      throw new Error(`Operation '${toolName}' denied: ${decision.reason}`);
    }

    return fn(...args);
  };

  return wrapped as T;
}
