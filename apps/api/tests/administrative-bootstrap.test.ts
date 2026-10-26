import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { Express } from 'express';
import {
  AuthorizationEngine,
  PlatformRoles,
  AuthorizationError,
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

  const superadminId = 'superadmin-uuid-001';
  const superadminToken = 'superadmin-bearer-token';
  const superadminEmail = 'superadmin.modularauth@gmail.com';

  const adminId = 'admin-uuid-002';
  const adminToken = 'admin-bearer-token';
  const adminEmail = 'admin.modularauth@gmail.com';

  const ordinaryUserId = 'ordinary-uuid-003';
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
  });
});
