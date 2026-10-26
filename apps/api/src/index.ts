import { env } from './config/env.js';
import { createApp } from './app.js';
import { SupabaseTokenVerifier } from './services/token-verifier.js';
import { ConsoleAuditLogger } from './services/audit-logger.js';
import { AuthorizationEngine } from '@modular-auth/core';
import { SupabaseUserService } from './services/user-service.js';
import { SupabaseOrganizationService } from './services/organization-service.js';

const tokenVerifier = new SupabaseTokenVerifier({
  jwtSecret: env.SUPABASE_JWT_SECRET,
  supabaseUrl: env.SUPABASE_URL,
});

const authzEngine = new AuthorizationEngine();
const auditLogger = new ConsoleAuditLogger();

// Instantiate database services connected to Supabase PostgreSQL
const userService = new SupabaseUserService({
  supabaseUrl: env.SUPABASE_URL,
  serviceRoleKey: env.SUPABASE_SERVICE_ROLE_KEY,
});

const orgService = new SupabaseOrganizationService({
  supabaseUrl: env.SUPABASE_URL,
  serviceRoleKey: env.SUPABASE_SERVICE_ROLE_KEY,
});

const app = createApp({
  tokenVerifier,
  authzEngine,
  orgService,
  userService,
  auditLogger,
  corsOrigin: env.CORS_ORIGIN,
  rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS,
  rateLimitMax: env.RATE_LIMIT_MAX_REQUESTS,
  authRateLimitMax: env.AUTH_RATE_LIMIT_MAX_REQUESTS,
});

app.listen(env.PORT, () => {
  console.log(`[API Server] Modular Auth API listening securely on port ${env.PORT} in ${env.NODE_ENV} mode`);
});
