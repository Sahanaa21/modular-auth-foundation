import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { Express } from 'express';
import {
  AuthorizationEngine,
  PlatformRoles,
  OrgRoles,
  IOrganizationService,
  OrganizationMembership,
  Organization,
  AuditEventTypes,
} from '@modular-auth/core';
import { createApp } from '../src/app.js';
import { MockTokenVerifier } from '../src/services/token-verifier.js';
import { InMemoryAuditLogger } from '../src/services/audit-logger.js';

// In-memory mock organization service for hermetic testing
class TestOrganizationService implements IOrganizationService {
  private readonly memberships = new Map<string, OrganizationMembership>();

  public addMembership(membership: OrganizationMembership): void {
    const key = `${membership.userId}:${membership.organizationId}`;
    this.memberships.set(key, membership);
  }

  public clear(): void {
    this.memberships.clear();
  }

  public async getUserMemberships(userId: string): Promise<readonly OrganizationMembership[]> {
    return Array.from(this.memberships.values()).filter((m) => m.userId === userId);
  }

  public async getMembership(userId: string, organizationId: string): Promise<OrganizationMembership | null> {
    const key = `${userId}:${organizationId}`;
    return this.memberships.get(key) ?? null;
  }

  public async getOrganizationById(organizationId: string): Promise<Organization | null> {
    return {
      id: organizationId,
      name: `Org ${organizationId}`,
      slug: `org-${organizationId}`,
      status: 'active',
      createdAt: new Date(),
    };
  }
}

describe('API Security Middleware Suite', () => {
  let app: Express;
  let tokenVerifier: MockTokenVerifier;
  let authzEngine: AuthorizationEngine;
  let orgService: TestOrganizationService;
  let auditLogger: InMemoryAuditLogger;

  const validToken = 'valid-test-token-uuid-1';
  const userId = 'user-uuid-100';
  const orgA = 'org-uuid-aaa';
  const orgB = 'org-uuid-bbb';

  beforeEach(() => {
    tokenVerifier = new MockTokenVerifier();
    authzEngine = new AuthorizationEngine();
    orgService = new TestOrganizationService();
    auditLogger = new InMemoryAuditLogger();

    // Register a valid token for user-uuid-100
    tokenVerifier.registerToken(validToken, {
      sub: userId,
      email: 'user@example.com',
      iss: 'https://example.supabase.co/auth/v1',
      aud: 'authenticated',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    app = createApp({
      tokenVerifier,
      authzEngine,
      orgService,
      auditLogger,
      authRateLimitMax: 3, // Low limit to test rate limiting quickly
    });
  });

  describe('Health Check & Security Headers', () => {
    it('returns 200 with standard health status and Helmet security headers', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('ok');
      // Verify security headers added by Helmet
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['strict-transport-security']).toBeDefined();
    });
  });

  describe('Authentication Enforcement', () => {
    it('rejects unauthenticated requests with HTTP 401 when Authorization header is missing', async () => {
      const response = await request(app).get('/api/v1/auth/me');

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
      expect(response.body.error.message).toContain('Missing Authorization header');
    });

    it('rejects requests with malformed Authorization header (no Bearer prefix)', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Basic user:pass');

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects expired tokens with HTTP 401', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer expired-token');

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
      expect(response.body.error.message).toContain('expired');
    });

    it('rejects forged / invalid signature tokens with HTTP 401', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer invalid-signature-token');

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
    });

    it('allows valid authenticated token and returns user identity context', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(200);
      expect(response.body.user.id).toBe(userId);
      expect(response.body.user.email).toBe('user@example.com');
    });
  });

  describe('Platform Role Isolation', () => {
    it('rejects regular users lacking a platform role from platform metrics (403)', async () => {
      // User has no platform role
      const response = await request(app)
        .get('/api/v1/platform/metrics')
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');
    });

    it('allows users with platform role Developer to access platform metrics', async () => {
      const devToken = 'dev-token-uuid';
      tokenVerifier.registerToken(devToken, {
        sub: 'dev-user-id',
        email: 'dev@company.com',
        iss: 'https://example.supabase.co/auth/v1',
        aud: 'authenticated',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        platform_role: PlatformRoles.DEVELOPER,
      });

      const response = await request(app)
        .get('/api/v1/platform/metrics')
        .set('Authorization', `Bearer ${devToken}`);

      expect(response.status).toBe(200);
      expect(response.body.scope).toBe('platform');
      expect(response.body.userRole).toBe(PlatformRoles.DEVELOPER);
    });

    it('restricts system settings to Founder only (Developer receives 403)', async () => {
      const devToken = 'dev-token-uuid-2';
      tokenVerifier.registerToken(devToken, {
        sub: 'dev-user-id-2',
        email: 'dev2@company.com',
        iss: 'https://example.supabase.co/auth/v1',
        aud: 'authenticated',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        platform_role: PlatformRoles.DEVELOPER,
      });

      const response = await request(app)
        .get('/api/v1/platform/system-settings')
        .set('Authorization', `Bearer ${devToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('Organization Tenancy & Membership Enforcement', () => {
    it('rejects access to organization route when user is NOT a member of that organization (403)', async () => {
      // User is not a member of orgA
      const response = await request(app)
        .get(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('TENANT_ACCESS_DENIED');
      expect(response.body.error.message).toContain('not an active member');
    });

    it('rejects access when membership is suspended (403)', async () => {
      orgService.addMembership({
        id: 'mem-1',
        userId,
        organizationId: orgA,
        role: OrgRoles.LEADER,
        status: 'suspended',
        createdAt: new Date(),
      });

      const response = await request(app)
        .get(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('TENANT_ACCESS_DENIED');
    });

    it('CRITICAL IDOR: Rejects attempt to access Organization B when user only has membership in Organization A', async () => {
      // User is active Business Owner in Org A
      orgService.addMembership({
        id: 'mem-orgA',
        userId,
        organizationId: orgA,
        role: OrgRoles.BUSINESS_OWNER,
        status: 'active',
        createdAt: new Date(),
      });

      // User attempts to query Org B
      const response = await request(app)
        .get(`/api/v1/organizations/${orgB}/projects`)
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('TENANT_ACCESS_DENIED');
    });
  });

  describe('Permission-Based Access Control (PBAC)', () => {
    beforeEach(() => {
      // Setup user as an active Intern in Org A
      orgService.addMembership({
        id: 'mem-intern',
        userId,
        organizationId: orgA,
        role: OrgRoles.INTERN,
        status: 'active',
        createdAt: new Date(),
      });
    });

    it('allows Intern to read projects (has resource:read permission)', async () => {
      const response = await request(app)
        .get(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(200);
      expect(response.body.projects).toHaveLength(2);
    });

    it('rejects Intern attempting to create project (lacks resource:create permission) and logs audit event', async () => {
      const response = await request(app)
        .post(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ name: 'Unauthorized Project' });

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');

      // Verify security audit log captured the denial
      const deniedEvents = auditLogger.findEventsByType(AuditEventTypes.AUTHZ_ACCESS_DENIED);
      expect(deniedEvents).toHaveLength(1);
      expect(deniedEvents[0].actorId).toBe(userId);
      expect(deniedEvents[0].organizationId).toBe(orgA);
      expect(deniedEvents[0].outcome).toBe('DENIED');
    });

    it('rejects Intern attempting to invite a member (lacks member:invite)', async () => {
      const response = await request(app)
        .post(`/api/v1/organizations/${orgA}/members`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ email: 'new@example.com', role: 'guest' });

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('Input Validation & Zod Schema Enforcement', () => {
    beforeEach(() => {
      // User is active Manager in Org A
      orgService.addMembership({
        id: 'mem-mgr',
        userId,
        organizationId: orgA,
        role: OrgRoles.MANAGER,
        status: 'active',
        createdAt: new Date(),
      });
    });

    it('rejects invalid payload with HTTP 400 and structured validation details', async () => {
      const response = await request(app)
        .post(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ name: '' }); // Empty name fails .min(1)

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.details).toBeDefined();
    });

    it('accepts valid project creation payload and returns 201 Created', async () => {
      const response = await request(app)
        .post(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ name: 'Valid Project', description: 'Sample description' });

      expect(response.status).toBe(201);
      expect(response.body.project.name).toBe('Valid Project');
    });
  });

  describe('Rate Limiting on Sensitive Auth Routes', () => {
    it('enforces rate limiting when exceeding threshold on sensitive route (HTTP 429)', async () => {
      const validPayload = { email: 'test@example.com', password: 'password123' };

      // Make 3 allowed requests (authRateLimitMax: 3)
      await request(app).post('/api/v1/auth/login-attempt').send(validPayload).expect(200);
      await request(app).post('/api/v1/auth/login-attempt').send(validPayload).expect(200);
      await request(app).post('/api/v1/auth/login-attempt').send(validPayload).expect(200);

      // 4th request must be rate limited
      const response = await request(app).post('/api/v1/auth/login-attempt').send(validPayload);
      expect(response.status).toBe(429);
      expect(response.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });
  });
});
