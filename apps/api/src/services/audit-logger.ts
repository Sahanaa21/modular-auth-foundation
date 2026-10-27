import { IAuditLogger, SecurityAuditEvent } from '@modular-auth/core';

const SENSITIVE_KEYS = new Set([
  'password',
  'token',
  'accesstoken',
  'refreshtoken',
  'secret',
  'authorization',
  'cookie',
  'apikey',
  'key',
  'session',
]);

/**
 * Sanitizes arbitrary metadata objects to strictly prevent secret leakage in audit logs.
 */
export function sanitizeAuditMetadata(metadata?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!metadata) {
    return undefined;
  }

  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(metadata)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_KEYS.has(lowerKey)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      sanitized[key] = sanitizeAuditMetadata(value as Record<string, unknown>);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Standard structured logger for security audit events.
 */
export class ConsoleAuditLogger implements IAuditLogger {
  public async logEvent(event: SecurityAuditEvent): Promise<void> {
    const sanitizedEvent: SecurityAuditEvent = {
      ...event,
      metadata: sanitizeAuditMetadata(event.metadata),
    };

    // Format as structured JSON log line for observability platforms
    const logLine = JSON.stringify({
      level: event.outcome === 'SUCCESS' ? 'INFO' : 'WARN',
      timestamp: sanitizedEvent.timestamp.toISOString(),
      type: 'SECURITY_AUDIT',
      event: sanitizedEvent,
    });

    if (event.outcome === 'FAILURE' || event.outcome === 'DENIED' || event.outcome === 'ERROR') {
      console.warn(logLine);
    } else {
      console.info(logLine);
    }
  }
}

/**
 * In-memory audit logger for test suites to assert security event emissions.
 */
export class InMemoryAuditLogger implements IAuditLogger {
  public readonly events: SecurityAuditEvent[] = [];

  public getEvents(): readonly SecurityAuditEvent[] {
    return this.events;
  }

  public async logEvent(event: SecurityAuditEvent): Promise<void> {
    this.events.push({
      ...event,
      metadata: sanitizeAuditMetadata(event.metadata),
    });
  }

  public clear(): void {
    this.events.length = 0;
  }

  public findEventsByType(type: string): SecurityAuditEvent[] {
    return this.events.filter((e) => e.eventType === type);
  }
}
