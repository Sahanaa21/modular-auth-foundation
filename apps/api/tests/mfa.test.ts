import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { Express } from 'express';
import {
  AuthorizationEngine,
  PlatformRoles,
  IOrganizationService,
  OrganizationMembership,
  Organization,
} from '@modular-auth/core';
import { createApp } from '../src/app.js';
import { MockTokenVerifier } from '../src/services/token-verifier.js';
import { InMemoryAuditLogger } from '../src/services/audit-logger.js';
import { InMemoryUserService } from '../src/services/user-service.js';
import { InMemoryMFAProvider } from '../src/services/mfa-service.js';

class MockOrgService implements IOrganizationService {
  public async getUserMemberships(_userId: string): Promise<readonly OrganizationMembership[]> {
    return [];
  }
  public async getMembership(_userId: string, _orgId: string): Promise<OrganizationMembership | null> {
    return null;
  }
  public async getOrganizationById(id: string): Promise<Organization | null> {
    return { id, name: id, slug: id, status: 'active', createdAt: new Date() };
  }
}

describe('MFA Framework and Step-Up Verification Suite', () => {
  let app: Express;
  let tokenVerifier: MockTokenVerifier;
  let userService: InMemoryUserService;
  let mfaProvider: InMemoryMFAProvider;

  const superadminId = 'd6d1bbef-e141-4138-ac74-987070d05527';
  const aal1Token = 'token-with-aal1-only';
  const aal2Token = 'token-with-verified-aal2';
  const nonAdminToken = 'token-ordinary-user';

  beforeEach(() => {
    tokenVerifier = new MockTokenVerifier();
    userService = new InMemoryUserService();
    mfaProvider = new InMemoryMFAProvider();

    // Register superadmin with single-factor token (aal1)
    tokenVerifier.registerToken(aal1Token, {
      sub: superadminId,
      email: 'superadmin.modularauth@gmail.com',
      iss: 'https://example.supabase.co/auth/v1',
      aud: 'authenticated',
      aal: 'aal1',
      amr: ['password'],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    // Register superadmin with multi-factor token (aal2)
    tokenVerifier.registerToken(aal2Token, {
      sub: superadminId,
      email: 'superadmin.modularauth@gmail.com',
      iss: 'https://example.supabase.co/auth/v1',
      aud: 'authenticated',
      aal: 'aal2',
      amr: ['password', 'totp'],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    // Register ordinary user (developer role)
    const ordinaryUserId = 'user-developer-uuid';
    tokenVerifier.registerToken(nonAdminToken, {
      sub: ordinaryUserId,
      email: 'dev@archscale.com',
      iss: 'https://example.supabase.co/auth/v1',
      aud: 'authenticated',
      aal: 'aal2',
      amr: ['password', 'totp'],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    userService.setUser(superadminId, 'superadmin.modularauth@gmail.com', PlatformRoles.SUPER_ADMIN);
    userService.setUser(ordinaryUserId, 'dev@archscale.com', PlatformRoles.DEVELOPER);

    app = createApp({
      tokenVerifier,
      authzEngine: new AuthorizationEngine(),
      orgService: new MockOrgService(),
      userService,
      auditLogger: new InMemoryAuditLogger(),
      mfaProvider,
    });
  });

  describe('requireMFA Middleware Enforcement on Protected Routes', () => {
    it('rejects unauthenticated requests with HTTP 401', async () => {
      const response = await request(app).post('/api/v1/platform/sensitive-operation');
      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects requests possessing only AAL1 (single-factor) with HTTP 403 MFA_REQUIRED', async () => {
      const response = await request(app)
        .post('/api/v1/platform/sensitive-operation')
        .set('Authorization', `Bearer ${aal1Token}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('MFA_REQUIRED');
      expect(response.body.error.message).toContain('Multi-factor authentication (AAL2) required');
      expect(response.body.error.details.currentAssuranceLevel).toBe('aal1');
      expect(response.body.error.details.requiredAssuranceLevel).toBe('aal2');
    });

    it('permits requests possessing verified AAL2 (multi-factor) assurance with HTTP 200', async () => {
      const response = await request(app)
        .post('/api/v1/platform/sensitive-operation')
        .set('Authorization', `Bearer ${aal2Token}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toContain('Step-up MFA verified successfully');
      expect(response.body.assuranceLevel).toBe('aal2');
      expect(response.body.amr).toContain('totp');
    });

    it('rejects users lacking required platform role even if possessing AAL2', async () => {
      const response = await request(app)
        .post('/api/v1/platform/sensitive-operation')
        .set('Authorization', `Bearer ${nonAdminToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('MFA Provider Factor Lifecycle (TOTP)', () => {
    it('enrolls, challenges, and verifies a TOTP factor through the provider interface', async () => {
      const userId = 'user-totp-test';

      // 1. Enroll
      const enrollment = await mfaProvider.enrollFactor(userId, 'totp', 'Work Authenticator');
      expect(enrollment.factorId).toBeDefined();
      expect(enrollment.factorType).toBe('totp');
      expect(enrollment.secret).toBeDefined();
      expect(enrollment.totpUri).toContain('otpauth://totp');

      // Check listed factors
      const factorsBefore = await mfaProvider.listFactors(userId);
      expect(factorsBefore).toHaveLength(1);
      expect(factorsBefore[0].status).toBe('unverified');

      // 2. Issue challenge
      const challenge = await mfaProvider.challengeFactor(enrollment.factorId);
      expect(challenge.factorId).toBe(enrollment.factorId);
      expect(challenge.expiresAt.getTime()).toBeGreaterThan(Date.now());

      // 3. Verify challenge with invalid code
      const invalidResult = await mfaProvider.verifyChallenge(challenge.id, '000000');
      expect(invalidResult.verified).toBe(false);
      expect(invalidResult.aal).toBe('aal1');

      // 4. Verify challenge with correct code
      const validResult = await mfaProvider.verifyChallenge(challenge.id, '123456');
      expect(validResult.verified).toBe(true);
      expect(validResult.aal).toBe('aal2');

      // Check factor status now verified
      const factorsAfter = await mfaProvider.listFactors(userId);
      expect(factorsAfter[0].status).toBe('verified');

      // 5. Unenroll factor
      await mfaProvider.unenrollFactor(userId, enrollment.factorId);
      const factorsRemaining = await mfaProvider.listFactors(userId);
      expect(factorsRemaining).toHaveLength(0);
    });
  });
});
