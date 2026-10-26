import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createModularAuthPlugin } from '../src/plugin.js';
import { InMemoryUserService } from '../src/services/user-service.js';
import { InMemoryAuditLogger } from '../src/services/audit-logger.js';
import { MockTokenVerifier } from '../src/services/token-verifier.js';
import { PlatformRoles } from '@modular-auth/core';

describe('Official Modular Auth Plugin Suite', () => {
  it('instantiates as an official Express plugin and responds to health check', async () => {
    const pluginApp = createModularAuthPlugin({
      supabaseUrl: 'https://vsllykwuqqmbitxvpuod.supabase.co',
      serviceRoleKey: 'test-service-role-key',
    });

    const response = await request(pluginApp).get('/health');
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('ok');
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['x-frame-options']).toBe('DENY');
  });

  it('allows overriding dependencies for custom integration pipelines', async () => {
    const userService = new InMemoryUserService();
    const auditLogger = new InMemoryAuditLogger();
    const tokenVerifier = new MockTokenVerifier();

    const superadminId = 'd6d1bbef-e141-4138-ac74-987070d05527';
    const targetAdminId = 'a800ea5c-667a-424a-aa09-49f6a4a8a222';
    const token = 'plugin-test-token';

    userService.setUser(superadminId, 'superadmin@example.com', PlatformRoles.SUPER_ADMIN);
    userService.setUser(targetAdminId, 'admin@example.com', null);

    tokenVerifier.registerToken(token, {
      sub: superadminId,
      email: 'superadmin@example.com',
      iss: 'https://vsllykwuqqmbitxvpuod.supabase.co/auth/v1',
      aud: 'authenticated',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const pluginApp = createModularAuthPlugin({
      supabaseUrl: 'https://vsllykwuqqmbitxvpuod.supabase.co',
      userService,
      auditLogger,
      tokenVerifier,
    });

    const response = await request(pluginApp)
      .patch(`/api/v1/platform/users/${targetAdminId}/role`)
      .set('Authorization', `Bearer ${token}`)
      .send({ role: 'admin' });

    expect(response.status).toBe(200);
    expect(response.body.newRole).toBe('admin');
  });
});
