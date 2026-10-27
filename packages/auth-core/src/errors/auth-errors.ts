/**
 * Base error class for all authentication and authorization errors.
 * Ensures consistent serialization and error codes without leaking secrets or internals.
 */
export abstract class AuthBaseError extends Error {
  public abstract readonly statusCode: number;
  public abstract readonly code: string;
  public readonly details?: Record<string, unknown>;

  constructor(message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = this.constructor.name;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Safe, sanitized JSON representation for API responses.
   * Never includes stack traces or raw tokens.
   */
  public toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
      },
    };
  }
}

/**
 * Thrown when an authentication check fails (missing, expired, or invalid token).
 * Maps to HTTP 401 Unauthorized.
 */
export class AuthenticationError extends AuthBaseError {
  public readonly statusCode = 401;
  public readonly code = 'UNAUTHENTICATED';

  constructor(message = 'Authentication required', details?: Record<string, unknown>) {
    super(message, details);
  }
}

/**
 * Thrown when an authenticated user lacks required permissions or roles.
 * Maps to HTTP 403 Forbidden.
 */
export class AuthorizationError extends AuthBaseError {
  public readonly statusCode = 403;
  public readonly code = 'FORBIDDEN';

  constructor(message = 'Access forbidden: Insufficient permissions', details?: Record<string, unknown>) {
    super(message, details);
  }
}

/**
 * Thrown when tenant/organization verification fails (not a member, suspended membership).
 * Maps to HTTP 403 Forbidden.
 */
export class TenantAccessError extends AuthBaseError {
  public readonly statusCode = 403;
  public readonly code = 'TENANT_ACCESS_DENIED';

  constructor(message = 'Access to the specified organization is denied', details?: Record<string, unknown>) {
    super(message, details);
  }
}

/**
 * Thrown when a cross-tenant resource access attempt or IDOR is detected.
 * In production, this can also map to HTTP 404 to avoid leaking resource existence.
 */
export class ResourceAccessError extends AuthBaseError {
  public readonly statusCode: number;
  public readonly code = 'RESOURCE_ACCESS_DENIED';

  constructor(
    message = 'Access to the requested resource is denied',
    statusCode = 403,
    details?: Record<string, unknown>
  ) {
    super(message, details);
    this.statusCode = statusCode;
  }
}

/**
 * Thrown when required environment variables or configuration options are missing or invalid.
 * Maps to HTTP 500 Internal Server Error.
 */
export class ConfigurationError extends AuthBaseError {
  public readonly statusCode = 500;
  public readonly code = 'CONFIGURATION_ERROR';

  constructor(message = 'Invalid or missing security configuration', details?: Record<string, unknown>) {
    super(message, details);
  }
}

/**
 * Thrown when a requested resource (such as a target user) is not found.
 * Maps to HTTP 404 Not Found.
 */
export class NotFoundError extends AuthBaseError {
  public readonly statusCode = 404;
  public readonly code = 'NOT_FOUND';

  constructor(message = 'Requested resource not found', details?: Record<string, unknown>) {
    super(message, details);
  }
}

/**
 * Thrown when an endpoint or operation requires multi-factor authentication (AAL2),
 * but the session only possesses single-factor (AAL1).
 * Maps to HTTP 403 Forbidden.
 */
export class MFAVerificationRequiredError extends AuthBaseError {
  public readonly statusCode = 403;
  public readonly code = 'MFA_REQUIRED';

  constructor(
    message = 'Multi-factor authentication (AAL2) verification required for this operation',
    details?: Record<string, unknown>
  ) {
    super(message, details);
  }
}

/**
 * Thrown when an account has not enrolled in mandatory MFA.
 * Maps to HTTP 403 Forbidden.
 */
export class MFAEnrollmentRequiredError extends AuthBaseError {
  public readonly statusCode = 403;
  public readonly code = 'MFA_ENROLLMENT_REQUIRED';

  constructor(
    message = 'MFA enrollment is required before accessing this protected resource',
    details?: Record<string, unknown>
  ) {
    super(message, details);
  }
}


