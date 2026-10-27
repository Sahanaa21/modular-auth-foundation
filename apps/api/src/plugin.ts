import { createClient, SupabaseClient } from '@supabase/supabase-js';
import {
  IAuthorizationEngine,
  AuthorizationEngine,
  IAuditLogger,
  ITokenVerifier,
  IOrganizationService,
  IMFAProvider,
} from '@modular-auth/core';
import { createApp } from './app.js';
import type { AppDependencies } from './app.js';
import { SupabaseTokenVerifier, MockTokenVerifier } from './services/token-verifier.js';
import { SupabaseUserService, InMemoryUserService } from './services/user-service.js';
import type { IUserService } from './services/user-service.js';
import { SupabaseOrganizationService } from './services/organization-service.js';
import { ConsoleAuditLogger, InMemoryAuditLogger } from './services/audit-logger.js';
import { SupabaseAuditLogger } from './services/supabase-audit-logger.js';
import { SupabaseMFAProvider, InMemoryMFAProvider } from './services/mfa-service.js';

// Re-export middleware for consumers building custom route pipelines
export { authenticate } from './middleware/authenticate.js';
export { requirePlatformRole } from './middleware/require-role.js';
export { requireOrgMembership, requireTenantMembership } from './middleware/require-org-membership.js';
export { requirePermission } from './middleware/require-permission.js';
export { requireMFA } from './middleware/require-mfa.js';
export { securityHeaders } from './middleware/security-headers.js';
export { corsMiddleware } from './middleware/cors.js';
export { createRateLimiter } from './middleware/rate-limiter.js';
export { errorHandler } from './middleware/error-handler.js';
export { validateRequest } from './middleware/validate-request.js';

// Re-export services & interfaces
export {
  SupabaseTokenVerifier,
  MockTokenVerifier,
  SupabaseUserService,
  InMemoryUserService,
  SupabaseOrganizationService,
  ConsoleAuditLogger,
  InMemoryAuditLogger,
  SupabaseAuditLogger,
  SupabaseMFAProvider,
  InMemoryMFAProvider,
  createApp,
};
export type { IUserService, AppDependencies, IMFAProvider };

/**
 * Configuration options for the Modular Auth Express Plugin.
 */
export interface ModularAuthPluginOptions {
  /** Supabase Project URL (e.g. https://<project>.supabase.co) */
  readonly supabaseUrl: string;
  /** Supabase service-role key for authoritative database lookups (optional for token-only auth) */
  readonly serviceRoleKey?: string;
  /** Legacy symmetric JWT secret (optional if project uses modern ES256/RS256 JWKS) */
  readonly jwtSecret?: string;
  /** Allowed CORS origins (e.g. 'http://localhost:5173') */
  readonly corsOrigin?: string;
  /** Custom user service override */
  readonly userService?: IUserService;
  /** Custom organization service override */
  readonly orgService?: IOrganizationService;
  /** Custom audit logger override */
  readonly auditLogger?: IAuditLogger;
  /** Custom authorization engine override */
  readonly authzEngine?: IAuthorizationEngine;
  /** Custom token verifier override */
  readonly tokenVerifier?: ITokenVerifier;
  /** Custom MFA provider override */
  readonly mfaProvider?: IMFAProvider;
  /** Rate limit window in milliseconds */
  readonly rateLimitWindowMs?: number;
  /** Global rate limit max requests per window */
  readonly rateLimitMax?: number;
  /** Sensitive auth route max requests per window */
  readonly authRateLimitMax?: number;
}

/**
 * Creates a fully configured Modular Auth Express application/router.
 *
 * Usage in external Node.js / Express applications:
 * ```typescript
 * import express from 'express';
 * import { createModularAuthPlugin } from '@modular-auth/api';
 *
 * const app = express();
 * const authPlugin = createModularAuthPlugin({
 *   supabaseUrl: process.env.SUPABASE_URL!,
 *   serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
 * });
 *
 * // Mount modular auth routes
 * app.use('/auth', authPlugin);
 * ```
 */
export function createModularAuthPlugin(options: ModularAuthPluginOptions) {
  let supabaseClient: SupabaseClient | undefined;
  if (options.serviceRoleKey && !options.serviceRoleKey.includes('placeholder')) {
    supabaseClient = createClient(options.supabaseUrl, options.serviceRoleKey, {
      auth: { persistSession: false },
    });
  }

  const tokenVerifier =
    options.tokenVerifier ??
    new SupabaseTokenVerifier({
      jwtSecret: options.jwtSecret,
      supabaseUrl: options.supabaseUrl,
      supabaseClient,
    });

  const authzEngine = options.authzEngine ?? new AuthorizationEngine();
  const auditLogger =
    options.auditLogger ??
    (supabaseClient
      ? new SupabaseAuditLogger({ supabaseClient, fallbackLogger: new ConsoleAuditLogger() })
      : new ConsoleAuditLogger());

  const userService =
    options.userService ??
    new SupabaseUserService({
      supabaseUrl: options.supabaseUrl,
      serviceRoleKey: options.serviceRoleKey,
      supabaseClient,
    });

  const orgService =
    options.orgService ??
    new SupabaseOrganizationService({
      supabaseUrl: options.supabaseUrl,
      serviceRoleKey: options.serviceRoleKey,
      supabaseClient,
    });

  const mfaProvider =
    options.mfaProvider ??
    new SupabaseMFAProvider({
      supabaseClient,
    });

  return createApp({
    tokenVerifier,
    authzEngine,
    orgService,
    userService,
    auditLogger,
    mfaProvider,
    corsOrigin: options.corsOrigin,
    rateLimitWindowMs: options.rateLimitWindowMs,
    rateLimitMax: options.rateLimitMax,
    authRateLimitMax: options.authRateLimitMax,
  });
}
