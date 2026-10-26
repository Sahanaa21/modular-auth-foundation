import { env } from './config/env.js';
import { createApp } from './app.js';
import { SupabaseTokenVerifier } from './services/token-verifier.js';
import { ConsoleAuditLogger } from './services/audit-logger.js';
import {
  AuthorizationEngine,
  IOrganizationService,
  OrganizationMembership,
  Organization,
} from '@modular-auth/core';

// In production, OrganizationService queries Supabase PostgreSQL.
// Here we provide the initial service adapter.
class DefaultOrganizationService implements IOrganizationService {
  public async getUserMemberships(userId: string): Promise<readonly OrganizationMembership[]> {
    return [
      {
        id: 'mem-default-1',
        userId,
        organizationId: 'org-demo-1',
        role: 'business_owner',
        status: 'active',
        createdAt: new Date(),
      },
    ];
  }

  public async getMembership(userId: string, organizationId: string): Promise<OrganizationMembership | null> {
    if (organizationId === 'org-demo-1') {
      return {
        id: 'mem-default-1',
        userId,
        organizationId,
        role: 'business_owner',
        status: 'active',
        createdAt: new Date(),
      };
    }
    return null;
  }

  public async getOrganizationById(organizationId: string): Promise<Organization | null> {
    if (organizationId === 'org-demo-1') {
      return {
        id: 'org-demo-1',
        name: 'Demo Workspace',
        slug: 'demo-workspace',
        status: 'active',
        createdAt: new Date(),
      };
    }
    return null;
  }
}

const tokenVerifier = new SupabaseTokenVerifier({
  jwtSecret: env.SUPABASE_JWT_SECRET,
  supabaseUrl: env.SUPABASE_URL,
});

const authzEngine = new AuthorizationEngine();
const orgService = new DefaultOrganizationService();
const auditLogger = new ConsoleAuditLogger();

const app = createApp({
  tokenVerifier,
  authzEngine,
  orgService,
  auditLogger,
  corsOrigin: env.CORS_ORIGIN,
  rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS,
  rateLimitMax: env.RATE_LIMIT_MAX_REQUESTS,
  authRateLimitMax: env.AUTH_RATE_LIMIT_MAX_REQUESTS,
});

app.listen(env.PORT, () => {
  console.log(`[API Server] Modular Auth API listening securely on port ${env.PORT} in ${env.NODE_ENV} mode`);
});
