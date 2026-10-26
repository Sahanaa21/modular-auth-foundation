import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { Express } from 'express';
import {
  AuthorizationEngine,
  PlatformRoles,
  AuthorizationError,
  ConfigurationError,
} from '@modular-auth/core';
import { createApp } from '../src/app.js';
import { MockTokenVerifier } from '../src/services/token-verifier.js';
import { InMemoryAuditLogger } from '../src/services/audit-logger.js';
import { InMemoryUserService } from '../src/services/user-service.js';
import { InMemoryOrganizationService } from '../src/services/organization-service.js';

describe('Administrative Provisioning & Bootstrap Suite', () => {
  let app: Express;
  let tokenVerifier: MockTokenVerifier;
  let authzEngine: AuthorizationEngine;
  let orgService: InMemoryOrganizationService;
  let userService: InMemoryUserService;
  let auditLogger: InMemoryAuditLogger;

  const superadminId = 'd6d1bbef-e141-4138-ac74-987070d05527';
  const superadminToken = 'superadmin-bearer-token';
  const superadminEmail = 'superadmin.modularauth@gmail.com';

  const adminId = 'a800ea5c-667a-424a-aa09-49f6a4a8a222';
  const adminToken = 'admin-bearer-token';
  const adminEmail = 'admin.modularauth@gmail.com';

  const ordinaryUserId = '00000000-0000-4000-8000-000000000003';
  const ordinaryToken = 'ordinary-bearer-token';

  beforeEach(() => {
    tokenVerifier = new MockTokenVerifier();
    authzEngine = new AuthorizationEngine();
    orgService = new InMemoryOrganizationService();
    userService = new InMemoryUserService();
    auditLogger = new InMemoryAuditLogger();

    // Register tokens
    tokenVerifier.registerToken(superadminToken, {
      sub: superadminId,
      email: superadminEmail,
      iss: 'https://example.supabase.co/auth/v1',
      aud: 'authenticated',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    tokenVerifier.registerToken(adminToken, {
      sub: adminId,
      email: adminEmail,
      iss: 'https://example.supabase.co/auth/v1',
      aud: 'authenticated',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    tokenVerifier.registerToken(ordinaryToken, {
      sub: ordinaryUserId,
      email: 'user@example.com',
      iss: 'https://example.supabase.co/auth/v1',
      aud: 'authenticated',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    // Populate initial state: users exist in database with platformRole = null
    userService.setUser(superadminId, superadminEmail, null);
    userService.setUser(adminId, adminEmail, null);
    userService.setUser(ordinaryUserId, 'user@example.com', null);

    app = createApp({
      tokenVerifier,
      authzEngine,
      orgService,
      userService,
      auditLogger,
    });
  });

  describe('Initial Superadmin Bootstrap Procedure', () => {
    it('successfully provisions the initial superadmin when no superadmin exists', async () => {
      // Pre-condition: superadmin has platformRole = null
      const initialProfile = await userService.getUserProfile(superadminId);
      expect(initialProfile?.platformRole).toBeNull();

      // Execute bootstrap
      await userService.bootstrapSuperadmin(superadminId);

      // Verify role assigned
      const postBootstrapProfile = await userService.getUserProfile(superadminId);
      expect(postBootstrapProfile?.platformRole).toBe(PlatformRoles.SUPER_ADMIN);
    });

    it('permanently locks and rejects repeated bootstrap attempts once a superadmin exists', async () => {
      // First bootstrap succeeds
      await userService.bootstrapSuperadmin(superadminId);

      // Attempt duplicate bootstrap for another user (or same user)
      await expect(userService.bootstrapSuperadmin(adminId)).rejects.toThrow(
        AuthorizationError
      );
      await expect(userService.bootstrapSuperadmin(adminId)).rejects.toThrow(
        /Bootstrap locked: An initial Super Administrator or Founder already exists/
      );
    });

    it('safely handles concurrent bootstrap attempts ensuring only one succeeds', async () => {
      const candidate1 = superadminId;
      const candidate2 = adminId;

      // Launch both bootstrap operations simultaneously
      const results = await Promise.allSettled([
        userService.bootstrapSuperadmin(candidate1),
        userService.bootstrapSuperadmin(candidate2),
      ]);

      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected = results.filter((r) => r.status === 'rejected');

      // Exactly ONE must succeed and the other must be rejected
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);

      // The rejected one must have failed due to the bootstrap lock
      const rejectionReason = (rejected[0] as PromiseRejectedResult).reason;
      expect(rejectionReason.message).toContain('Bootstrap locked');
    });
  });

  describe('Post-Bootstrap Role Delegation via Authenticated API', () => {
    beforeEach(async () => {
      // Perform initial bootstrap: superadmin is now provisioned
      await userService.bootstrapSuperadmin(superadminId);
    });

    it('allows authenticated Superadmin to assign Admin role to the second account', async () => {
      const response = await request(app)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(200);
      expect(response.body.newRole).toBe('admin');

      // Verify database updated
      const adminProfile = await userService.getUserProfile(adminId);
      expect(adminProfile?.platformRole).toBe(PlatformRoles.ADMIN);
    });

    it('rejects an Admin attempting to promote another user (403 Forbidden)', async () => {
      // First assign admin role to admin user
      await userService.updatePlatformRole(PlatformRoles.SUPER_ADMIN, adminId, PlatformRoles.ADMIN);

      // Admin user attempts to assign platform role to ordinary user
      const response = await request(app)
        .patch(`/api/v1/platform/users/${ordinaryUserId}/role`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');
    });

    it('rejects an ordinary user attempting to assign a platform role (403 Forbidden)', async () => {
      const response = await request(app)
        .patch(`/api/v1/platform/users/${ordinaryUserId}/role`)
        .set('Authorization', `Bearer ${ordinaryToken}`)
        .send({ role: 'superadmin' });

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');
    });

    it('rejects unauthenticated role assignment attempts (401 Unauthorized)', async () => {
      const response = await request(app)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .send({ role: 'admin' });

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects invalid or non-existent platform role strings (400 Bad Request)', async () => {
      const response = await request(app)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'unauthorized_super_god_mode' });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('allows authenticated Founder to assign an allowed platform role', async () => {
      const founderId = '00000000-0000-4000-8000-000000000004';
      const founderToken = 'founder-bearer-token';
      tokenVerifier.registerToken(founderToken, {
        sub: founderId,
        email: 'founder@archscale.com',
        iss: 'https://example.supabase.co/auth/v1',
        aud: 'authenticated',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      userService.setUser(founderId, 'founder@archscale.com', PlatformRoles.FOUNDER);

      const response = await request(app)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .set('Authorization', `Bearer ${founderToken}`)
        .send({ role: 'developer' });

      expect(response.status).toBe(200);
      expect(response.body.newRole).toBe('developer');

      const adminProfile = await userService.getUserProfile(adminId);
      expect(adminProfile?.platformRole).toBe(PlatformRoles.DEVELOPER);
    });

    it('prevents self-modification of platform role to avert administrative lockout (403 Forbidden)', async () => {
      const response = await request(app)
        .patch(`/api/v1/platform/users/${superadminId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'developer' });

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('FORBIDDEN');
      expect(response.body.error.message).toContain('Self-modification of platform role is forbidden');

      // Verify audit log recorded the denied self-modification attempt
      const deniedEvents = auditLogger.events.filter(
        (e) => e.eventType === 'authz:platform_role_updated' && e.outcome === 'DENIED'
      );
      expect(deniedEvents.length).toBeGreaterThan(0);
      expect(deniedEvents[0].actorId).toBe(superadminId);
      expect(deniedEvents[0].resourceId).toBe(superadminId);
    });

    it('rejects invalid target UUID format with 400 Bad Request', async () => {
      const response = await request(app)
        .patch('/api/v1/platform/users/not-a-valid-uuid/role')
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.details[0].field).toBe('targetUserId');
    });

    it('returns 404 Not Found when attempting to update a missing target user', async () => {
      const nonExistentUserId = '00000000-0000-4000-8000-000000000999';

      const response = await request(app)
        .patch(`/api/v1/platform/users/${nonExistentUserId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(404);
      expect(response.body.error.code).toBe('NOT_FOUND');
      expect(response.body.error.message).toContain('not found');
    });

    it('emits an audit log event with persisted role on successful role update', async () => {
      auditLogger.clear();

      const response = await request(app)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(200);

      const auditEvent = auditLogger.events.find(
        (e) => e.eventType === 'authz:platform_role_updated' && e.outcome === 'SUCCESS'
      );
      expect(auditEvent).toBeDefined();
      expect(auditEvent?.actorId).toBe(superadminId);
      expect(auditEvent?.resourceId).toBe(adminId);
      expect(auditEvent?.metadata?.persistedRole).toBe('admin');
    });

    it('propagates database error as 500 without false success', async () => {
      // Mock updatePlatformRole to throw database error
      const mockUserService = {
        ...userService,
        getUserProfile: userService.getUserProfile.bind(userService),
        bootstrapSuperadmin: userService.bootstrapSuperadmin.bind(userService),
        updatePlatformRole: async () => {
          throw new Error('Connection pool exhausted: Postgres connection failed');
        },
      };

      const failingApp = createApp({
        tokenVerifier,
        authzEngine,
        orgService,
        userService: mockUserService,
        auditLogger,
      });

      const response = await request(failingApp)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(500);
      expect(response.body.error.code).toBe('INTERNAL_SERVER_ERROR');
    });

    it('returns 500 CONFIGURATION_ERROR when user profile cannot be resolved due to missing database credentials (fail-closed)', async () => {
      const unconfiguredUserService = {
        ...userService,
        getUserProfile: async () => {
          throw new ConfigurationError(
            'Supabase client is not initialized: SUPABASE_SERVICE_ROLE_KEY is required to authoritatively load user roles from public.users.'
          );
        },
        bootstrapSuperadmin: userService.bootstrapSuperadmin.bind(userService),
        updatePlatformRole: userService.updatePlatformRole.bind(userService),
      };

      const unconfiguredApp = createApp({
        tokenVerifier,
        authzEngine,
        orgService,
        userService: unconfiguredUserService,
        auditLogger,
      });

      const response = await request(unconfiguredApp)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(500);
      expect(response.body.error.code).toBe('CONFIGURATION_ERROR');
      expect(response.body.error.message).toContain('SUPABASE_SERVICE_ROLE_KEY is required');
    });

    it('hydrates platform role from app_metadata when present in token claims', async () => {
      const appMetaToken = 'token-with-app-metadata';
      const appMetaSuperadminId = '00000000-0000-4000-8000-000000000888';
      tokenVerifier.registerToken(appMetaToken, {
        sub: appMetaSuperadminId,
        email: 'appmeta.admin@example.com',
        iss: 'https://example.supabase.co/auth/v1',
        aud: 'authenticated',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        app_metadata: {
          platform_role: 'superadmin',
        },
      });

      const response = await request(app)
        .patch(`/api/v1/platform/users/${adminId}/role`)
        .set('Authorization', `Bearer ${appMetaToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(200);
      expect(response.body.newRole).toBe('admin');
    });
  });
});

