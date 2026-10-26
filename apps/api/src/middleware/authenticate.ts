import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  ITokenVerifier,
  UserIdentity,
  AuthenticationError,
  PlatformRole,
  isPlatformRole,
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

      // 1. Initial platform role from token claims (top-level or app_metadata)
      let platformRole: PlatformRole | null = null;
      const rawClaimRole =
        claims['platform_role'] ??
        (typeof claims['app_metadata'] === 'object' && claims['app_metadata'] !== null
          ? (claims['app_metadata'] as Record<string, unknown>)['platform_role'] ??
            (claims['app_metadata'] as Record<string, unknown>)['role']
          : undefined);

      if (typeof rawClaimRole === 'string') {
        const normalized = rawClaimRole.trim().toLowerCase();
        const canonical = normalized === 'super_admin' ? 'superadmin' : normalized;
        if (isPlatformRole(canonical)) {
          platformRole = canonical;
        }
      }

      // 2. Authoritative Database Hydration via userResolver (public.users)
      if (options.userResolver) {
        const userProfile = await options.userResolver(claims.sub);
        if (userProfile) {
          // If a public.users profile exists, its platformRole is authoritative
          platformRole = userProfile.platformRole ?? null;
        }
        console.info('[authenticate] Hydrated platform role for authenticated user:', {
          userId: claims.sub,
          hasRole: Boolean(platformRole),
          resolvedRole: platformRole ?? 'none',
        });
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
