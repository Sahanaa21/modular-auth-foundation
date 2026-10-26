import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  IAuthorizationEngine,
  Permission,
  ResourceAccessRequest,
  AuthorizationError,
  AuthenticationError,
  IAuditLogger,
  AuditEventTypes,
} from '@modular-auth/core';

export interface RequirePermissionOptions {
  readonly authzEngine: IAuthorizationEngine;
  readonly action: Permission;
  readonly resourceType: string;
  readonly resourceIdParam?: string;
  readonly auditLogger?: IAuditLogger;
}

/**
 * Middleware that evaluates granular RBAC/PBAC permissions against the request context.
 * Considers authenticated identity, tenant membership, requested action, and target resource.
 */
export function requirePermission(options: RequirePermissionOptions): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.auth?.user) {
        throw new AuthenticationError('Authentication required before checking permissions');
      }

      const resourceId = options.resourceIdParam ? req.params[options.resourceIdParam] : undefined;
      const organizationId = req.tenant?.organizationId;

      const accessRequest: ResourceAccessRequest = {
        action: options.action,
        resourceType: options.resourceType,
        organizationId,
        resourceId,
      };

      const decision = options.authzEngine.evaluate(
        req.auth.user.platformRole,
        req.tenant?.membership?.role,
        accessRequest
      );

      if (!decision.granted) {
        // Log access denial to security audit log
        if (options.auditLogger) {
          await options.auditLogger.logEvent({
            eventType: AuditEventTypes.AUTHZ_ACCESS_DENIED,
            timestamp: new Date(),
            actorId: req.auth.user.id,
            organizationId,
            resourceId,
            resourceType: options.resourceType,
            outcome: 'DENIED',
            reason: decision.reason,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            metadata: {
              attemptedAction: options.action,
              platformRole: req.auth.user.platformRole,
              orgRole: req.tenant?.membership?.role,
            },
          });
        }

        throw new AuthorizationError(decision.reason ?? 'Access denied by authorization policy');
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}
