import { SupabaseClient } from '@supabase/supabase-js';
import { IAuditLogger, SecurityAuditEvent } from '@modular-auth/core';
import { ConsoleAuditLogger } from './audit-logger.js';

export interface SupabaseAuditLoggerOptions {
  readonly supabaseClient?: SupabaseClient;
  readonly fallbackLogger?: IAuditLogger;
  /**
   * In strict compliance mode, database insertion errors throw an exception.
   * By default (false), audit errors fail gracefully and log a warning to prevent
   * blocking client operations when the database is under load.
   */
  readonly strictCompliance?: boolean;
}

/**
 * Production audit logger that persists immutable security audit events
 * to the `public.audit_logs` PostgreSQL table via Supabase service-role client.
 */
export class SupabaseAuditLogger implements IAuditLogger {
  private readonly supabase?: SupabaseClient;
  private readonly fallbackLogger: IAuditLogger;
  private readonly strictCompliance: boolean;

  constructor(options: SupabaseAuditLoggerOptions = {}) {
    this.supabase = options.supabaseClient;
    this.fallbackLogger = options.fallbackLogger ?? new ConsoleAuditLogger();
    this.strictCompliance = options.strictCompliance ?? false;
  }

  public async logEvent(event: SecurityAuditEvent): Promise<void> {
    // 1. Emit to local fallback/console logger for real-time observability
    try {
      await this.fallbackLogger.logEvent(event);
    } catch {
      // Ignore console logging errors
    }

    // 2. Persist to PostgreSQL public.audit_logs if Supabase client is configured
    if (!this.supabase) {
      return;
    }

    try {
      // Sanitize metadata: strictly ensure no sensitive keys are persisted
      const sanitizedMeta = this.sanitizeMetadata({
        ...event.metadata,
        ...(event.action ? { action: event.action } : {}),
        ...(event.requestId ? { requestId: event.requestId } : {}),
        ...(event.correlationId ? { correlationId: event.correlationId } : {}),
        ...(event.workspaceId ? { workspaceId: event.workspaceId } : {}),
      });

      const { error } = await this.supabase.from('audit_logs').insert({
        event_type: event.eventType,
        timestamp: event.timestamp.toISOString(),
        actor_id: event.actorId,
        organization_id: event.organizationId ?? null,
        resource_id: event.resourceId ?? null,
        resource_type: event.resourceType ?? null,
        outcome: event.outcome,
        reason: event.reason ?? null,
        ip_address: event.ipAddress ?? null,
        user_agent: event.userAgent ?? null,
        metadata: sanitizedMeta,
      });

      if (error) {
        console.warn('[audit/db] Failed to persist audit event to public.audit_logs:', {
          eventType: event.eventType,
          error: error.message,
        });

        if (this.strictCompliance) {
          throw new Error(`Audit persistence failed: ${error.message}`);
        }
      }
    } catch (err) {
      if (this.strictCompliance) {
        throw err;
      }
      console.warn('[audit/db] Unexpected error persisting audit log:', err);
    }
  }

  /**
   * Strips any accidentally attached sensitive credentials before database persistence.
   */
  private sanitizeMetadata(metadata?: Record<string, unknown>): Record<string, unknown> {
    if (!metadata) {
      return {};
    }

    const sensitiveKeyPatterns = ['password', 'token', 'secret', 'key', 'credential', 'auth'];
    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(metadata)) {
      const lowerKey = key.toLowerCase();
      if (sensitiveKeyPatterns.some((pattern) => lowerKey.includes(pattern))) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        sanitized[key] = this.sanitizeMetadata(value as Record<string, unknown>);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }
}
