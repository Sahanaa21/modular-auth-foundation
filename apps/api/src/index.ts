import { env } from './config/env.js';
import { createApp } from './app.js';
import { SupabaseTokenVerifier } from './services/token-verifier.js';
import { ConsoleAuditLogger } from './services/audit-logger.js';
import { AuthorizationEngine } from '@modular-auth/core';
import { SupabaseUserService } from './services/user-service.js';
import { SupabaseOrganizationService } from './services/organization-service.js';
import { SupabaseAuditLogger } from './services/supabase-audit-logger.js';
import { SupabaseMFAProvider } from './services/mfa-service.js';

import { createClient } from '@supabase/supabase-js';

const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;
const isServiceRoleConfigured =
  Boolean(serviceRoleKey) &&
  !serviceRoleKey?.includes('placeholder') &&
  !serviceRoleKey?.includes('mock');

if (!isServiceRoleConfigured) {
  console.warn(
    '\x1b[33m%s\x1b[0m',
    '[API Server] WARNING: SUPABASE_SERVICE_ROLE_KEY is not configured or using a placeholder. ' +
    'Database operations against public.users will fail with "Invalid API key". ' +
    'Set a valid SUPABASE_SERVICE_ROLE_KEY in .env to connect to your Supabase PostgreSQL database.'
  );
} else {
  console.info('[API Server] SUPABASE_SERVICE_ROLE_KEY is configured. Authoritative public.users database operations active.');
}

const supabaseClient = isServiceRoleConfigured
  ? createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY!, {
      auth: { persistSession: false },
    })
  : undefined;

const tokenVerifier = new SupabaseTokenVerifier({
  jwtSecret: env.SUPABASE_JWT_SECRET,
  supabaseUrl: env.SUPABASE_URL,
  supabaseClient,
});

const authzEngine = new AuthorizationEngine();
const auditLogger = new SupabaseAuditLogger({
  supabaseClient,
  fallbackLogger: new ConsoleAuditLogger(),
});

// Instantiate database services connected to Supabase PostgreSQL
const userService = new SupabaseUserService({
  supabaseUrl: env.SUPABASE_URL,
  serviceRoleKey: env.SUPABASE_SERVICE_ROLE_KEY,
  supabaseClient,
});

const orgService = new SupabaseOrganizationService({
  supabaseUrl: env.SUPABASE_URL,
  serviceRoleKey: env.SUPABASE_SERVICE_ROLE_KEY,
  supabaseClient,
});

const mfaProvider = new SupabaseMFAProvider({
  supabaseClient,
});

const app = createApp({
  tokenVerifier,
  authzEngine,
  orgService,
  userService,
  auditLogger,
  mfaProvider,
  corsOrigin: env.CORS_ORIGIN,
  rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS,
  rateLimitMax: env.RATE_LIMIT_MAX_REQUESTS,
  authRateLimitMax: env.AUTH_RATE_LIMIT_MAX_REQUESTS,
});

const server = app.listen(env.PORT, () => {
  console.log(`[API Server] Modular Auth API listening securely on port ${env.PORT} in ${env.NODE_ENV} mode`);
});

// Graceful shutdown handling for containerized platforms (Render, Docker, Kubernetes)
const gracefulShutdown = (signal: string) => {
  console.info(`[API Server] Received ${signal}. Initiating graceful shutdown...`);
  server.close(() => {
    console.info('[API Server] HTTP server closed cleanly. Exiting process.');
    process.exit(0);
  });

  // Force close after 10 seconds if hanging connections exist
  const forceTimer = setTimeout(() => {
    console.error('[API Server] Forcing shutdown after timeout.');
    process.exit(1);
  }, 10000);

  forceTimer.unref();
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

