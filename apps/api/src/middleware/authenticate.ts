import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  ITokenVerifier,
  UserIdentity,
  AuthenticationError,
  PlatformRole,
} from '@modular-auth/core';

export interface AuthenticateMiddlewareOptions {
  readonly tokenVerifier: ITokenVerifier;
  /** Optional resolver to fetch user platform role from DB instead of token claims */
  readonly userResolver?: (userId: string) => Promise<{ platformRole?: PlatformRole | null } | null>;
}

/**
 * Middleware that extracts and verifies Bearer tokens on protected API routes.
 * Fails closed with 401 Unauthorized if token is missing, expired, or invalid.
 */
export function authenticate(options: AuthenticateMiddlewareOptions): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        throw new AuthenticationError('Missing Authorization header. Expected Bearer token.');
      }

      const [scheme, token] = authHeader.split(' ');
      if (scheme !== 'Bearer' || !token) {
        throw new AuthenticationError('Invalid Authorization header format. Expected "Bearer <token>".');
      }

      // Cryptographically verify token signature and claims
      const claims = await options.tokenVerifier.verifyToken(token);

      // Hydrate platform role from token claims or resolver
      let platformRole = (claims['platform_role'] as PlatformRole) || null;
      if (options.userResolver) {
        const userProfile = await options.userResolver(claims.sub);
        if (userProfile?.platformRole) {
          platformRole = userProfile.platformRole;
        }
      }

      const user: UserIdentity = {
        id: claims.sub,
        email: claims.email ?? '',
        isEmailVerified: Boolean(claims['email_verified'] ?? true),
        platformRole,
        userMetadata: (claims['user_metadata'] as Record<string, unknown>) ?? {},
        createdAt: claims.iat ? new Date(claims.iat * 1000) : new Date(),
      };

      // Attach authenticated context to Express Request
      req.auth = {
        user,
        claims,
        token,
      };

      next();
    } catch (error) {
      next(error);
    }
  };
}
