/**
 * Standard security audit event classifications.
 */
export const AuditEventTypes = {
  // Authentication events
  AUTH_SIGN_UP: 'auth:sign_up',
  AUTH_LOGIN_SUCCESS: 'auth:login_success',
  AUTH_LOGIN_FAILURE: 'auth:login_failure',
  AUTH_LOGOUT: 'auth:logout',
  AUTH_TOKEN_REFRESH: 'auth:token_refresh',
  AUTH_PASSWORD_RESET_REQUEST: 'auth:password_reset_request',
  AUTH_PASSWORD_RESET_SUCCESS: 'auth:password_reset_success',

  // Authorization and access control events
  AUTHZ_ACCESS_GRANTED: 'authz:access_granted',
  AUTHZ_ACCESS_DENIED: 'authz:access_denied',
  AUTHZ_IDOR_ATTEMPT: 'authz:idor_attempt',

  // Tenancy and membership events
  ORG_CREATED: 'org:created',
  ORG_MEMBER_INVITED: 'org:member_invited',
  ORG_MEMBER_ROLE_UPDATED: 'org:member_role_updated',
  ORG_MEMBER_REMOVED: 'org:member_removed',

  // Security policy & configuration events
  SECURITY_RATE_LIMIT_EXCEEDED: 'security:rate_limit_exceeded',
  SECURITY_CONFIG_VIOLATION: 'security:config_violation',
} as const;

export type AuditEventType = typeof AuditEventTypes[keyof typeof AuditEventTypes] | (string & {});

/**
 * Standard structured audit event entry.
 * Note: Never store plain secrets, passwords, or full bearer tokens in audit entries!
 */
export interface SecurityAuditEvent {
  /** Unique audit event identifier */
  readonly id?: string;
  /** Audit event classification */
  readonly eventType: AuditEventType;
  /** Timestamp when event occurred */
  readonly timestamp: Date;
  /** Identifier of the actor executing the action (user UUID or 'anonymous') */
  readonly actorId: string;
  /** Tenant organization context, if applicable */
  readonly organizationId?: string;
  /** Target resource identifier (e.g., project ID, user ID, invoice ID) */
  readonly resourceId?: string;
  /** Type of target resource */
  readonly resourceType?: string;
  /** Outcome status */
  readonly outcome: 'SUCCESS' | 'FAILURE' | 'DENIED' | 'ERROR';
  /** Reason or error code for failures/denials */
  readonly reason?: string;
  /** Client IP address (masked/hashed where privacy rules dictate) */
  readonly ipAddress?: string;
  /** Client User-Agent string */
  readonly userAgent?: string;
  /** Sanitized contextual metadata (no tokens, passwords, or PII) */
  readonly metadata?: Record<string, unknown>;
}

/**
 * Abstract interface for emitting and persisting security audit events.
 */
export interface IAuditLogger {
  /**
   * Records a security event. Fails gracefully without breaking request handling
   * unless configured in strict audit compliance mode.
   */
  logEvent(event: SecurityAuditEvent): Promise<void>;
}
