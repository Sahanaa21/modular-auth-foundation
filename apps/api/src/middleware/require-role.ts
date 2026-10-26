import { Request, Response, NextFunction, RequestHandler } from 'express';
import { PlatformRole, AuthorizationError, AuthenticationError } from '@modular-auth/core';

/**
 * Middleware that restricts routes to specific Platform-level roles.
 * E.g., founder, developer, accounts.
 */
export function requirePlatformRole(allowedRoles: readonly PlatformRole[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.auth?.user) {
      return next(new AuthenticationError('Authentication required to access platform route'));
    }

    const userRole = req.auth.user.platformRole;
    if (!userRole || !allowedRoles.includes(userRole)) {
      return next(
        new AuthorizationError(
          `Platform access denied. Required role in [${allowedRoles.join(', ')}], current role: '${userRole ?? 'none'}'`
        )
      );
    }

    next();
  };
}
