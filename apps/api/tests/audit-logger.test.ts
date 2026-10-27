import { describe, it, expect, vi } from 'vitest';
import { SecurityAuditEvent, AuditEventTypes } from '@modular-auth/core';
import { ConsoleAuditLogger, InMemoryAuditLogger } from '../src/services/audit-logger.js';
import { SupabaseAuditLogger } from '../src/services/supabase-audit-logger.js';
import { SupabaseClient } from '@supabase/supabase-js';

describe('Audit Logger Service Suite', () => {
  const sampleEvent: SecurityAuditEvent = {
    eventType: AuditEventTypes.AUTHZ_ACCESS_GRANTED,
    action: 'resource:create',
    timestamp: new Date(),
    actorId: 'user-actor-1',
    organizationId: 'org-tenant-1',
    workspaceId: 'ws-prod-1',
    resourceId: 'proj-123',
    resourceType: 'project',
    outcome: 'SUCCESS',
    requestId: 'req-abc-999',
    correlationId: 'corr-xyz-111',
    metadata: {
      projectName: 'Alpha Deployment',
      safeFlag: true,
      userPasswordAttempt: 'SecretPassword123!',
      clientApiKey: 'sk_live_123456789',
    },
  };

  it('records events in InMemoryAuditLogger and supports filtering', async () => {
    const inMemoryLogger = new InMemoryAuditLogger();
    await inMemoryLogger.logEvent(sampleEvent);

    const allEvents = inMemoryLogger.getEvents();
    expect(allEvents).toHaveLength(1);
    expect(allEvents[0].actorId).toBe('user-actor-1');

    const granted = inMemoryLogger.findEventsByType(AuditEventTypes.AUTHZ_ACCESS_GRANTED);
    expect(granted).toHaveLength(1);

    const denied = inMemoryLogger.findEventsByType(AuditEventTypes.AUTHZ_ACCESS_DENIED);
    expect(denied).toHaveLength(0);
  });

  it('formats audit logs safely without error in ConsoleAuditLogger', async () => {
    const consoleLogger = new ConsoleAuditLogger();
    const consoleSpy = vi.spyOn(console, 'info').mockImplementation(() => {});

    await consoleLogger.logEvent(sampleEvent);
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('persists audit events and redacts sensitive metadata in SupabaseAuditLogger', async () => {
    let capturedRow: Record<string, unknown> | null = null;

    const mockSupabase = {
      from: vi.fn().mockReturnValue({
        insert: vi.fn().mockImplementation((row) => {
          capturedRow = row;
          return Promise.resolve({ error: null });
        }),
      }),
    } as unknown as SupabaseClient;

    const inMemoryFallback = new InMemoryAuditLogger();
    const auditLogger = new SupabaseAuditLogger({
      supabaseClient: mockSupabase,
      fallbackLogger: inMemoryFallback,
    });

    await auditLogger.logEvent(sampleEvent);

    expect(mockSupabase.from).toHaveBeenCalledWith('audit_logs');
    expect(capturedRow).not.toBeNull();
    expect(capturedRow!.actor_id).toBe('user-actor-1');
    expect(capturedRow!.event_type).toBe(AuditEventTypes.AUTHZ_ACCESS_GRANTED);
    expect(capturedRow!.organization_id).toBe('org-tenant-1');

    // Verify sensitive keys were redacted
    const metadata = capturedRow!.metadata as Record<string, unknown>;
    expect(metadata.projectName).toBe('Alpha Deployment');
    expect(metadata.userPasswordAttempt).toBe('[REDACTED]');
    expect(metadata.clientApiKey).toBe('[REDACTED]');
    expect(metadata.action).toBe('resource:create');
    expect(metadata.requestId).toBe('req-abc-999');

    // Verify fallback logger was also updated
    expect(inMemoryFallback.getEvents()).toHaveLength(1);
  });

  it('fails gracefully when database insertion errors occur in non-strict mode', async () => {
    const mockSupabase = {
      from: vi.fn().mockReturnValue({
        insert: vi.fn().mockResolvedValue({ error: { message: 'DB connection timeout' } }),
      }),
    } as unknown as SupabaseClient;

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const auditLogger = new SupabaseAuditLogger({
      supabaseClient: mockSupabase,
      strictCompliance: false,
    });

    // Must NOT throw
    await expect(auditLogger.logEvent(sampleEvent)).resolves.not.toThrow();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[audit/db]'),
      expect.objectContaining({ error: 'DB connection timeout' })
    );

    warnSpy.mockRestore();
  });

  it('throws an error when database insertion errors occur in strict compliance mode', async () => {
    const mockSupabase = {
      from: vi.fn().mockReturnValue({
        insert: vi.fn().mockResolvedValue({ error: { message: 'Violates foreign key constraint' } }),
      }),
    } as unknown as SupabaseClient;

    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const strictLogger = new SupabaseAuditLogger({
      supabaseClient: mockSupabase,
      strictCompliance: true,
    });

    await expect(strictLogger.logEvent(sampleEvent)).rejects.toThrow('Audit persistence failed');
  });
});
