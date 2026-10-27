import { describe, it, expect, beforeEach } from 'vitest';
import express, { Express } from 'express';
import request from 'supertest';
import {
  IOrganizationService,
  OrganizationMembership,
  Organization,
  OrgRoles,
} from '@modular-auth/core';
import { requireTenantMembership } from '../src/middleware/require-org-membership.js';
import { errorHandler } from '../src/middleware/error-handler.js';

class MockTenantOrgService implements IOrganizationService {
  private readonly memberships = new Map<string, OrganizationMembership>();

  public addMembership(membership: OrganizationMembership) {
    this.memberships.set(`${membership.userId}:${membership.organizationId}`, membership);
  }

  public async getUserMemberships(userId: string): Promise<readonly OrganizationMembership[]> {
    return Array.from(this.memberships.values()).filter((m) => m.userId === userId);
  }

  public async getMembership(userId: string, organizationId: string): Promise<OrganizationMembership | null> {
    return this.memberships.get(`${userId}:${organizationId}`) ?? null;
  }

  public async getOrganizationById(id: string): Promise<Organization | null> {
    return { id, name: id, slug: id, status: 'active', createdAt: new Date() };
  }
}

describe('Tenant and Workspace Selection & Isolation Suite', () => {
  let app: Express;
  let orgService: MockTenantOrgService;

  const userId = 'user-tenant-123';
  const orgA = 'org-alpha';
  const orgB = 'org-beta';

  beforeEach(() => {
    orgService = new MockTenantOrgService();

    // Active member in Org A
    orgService.addMembership({
      id: 'mem-a',
      userId,
      organizationId: orgA,
      role: OrgRoles.LEADER,
      status: 'active',
      createdAt: new Date(),
    });

    // Inactive/suspended member in Org B
    orgService.addMembership({
      id: 'mem-b',
      userId,
      organizationId: orgB,
      role: OrgRoles.COLLABORATOR,
      status: 'suspended',
      createdAt: new Date(),
    });

    app = express();
    app.use(express.json());

    // Mock auth middleware for hermetic isolation
    app.use((req, _res, next) => {
      req.auth = {
        user: {
          id: userId,
          email: 'user@example.com',
          isEmailVerified: true,
          createdAt: new Date(),
        },
        claims: { sub: userId, iss: 'https://example.supabase.co', aud: 'authenticated', iat: 1, exp: 9999999999 },
        token: 'test-token',
      };
      next();
    });

    // Tenant-scoped route
    app.get(
      '/api/v1/organizations/:orgId/data',
      requireTenantMembership({ orgService }),
      (req, res) => {
        res.status(200).json({
          organizationId: req.tenant?.organizationId,
          workspaceId: req.tenant?.workspaceId,
          role: req.tenant?.membership.role,
        });
      }
    );

    // Workspace-scoped route
    app.get(
      '/api/v1/workspaces/:workspaceId/data',
      requireTenantMembership({ orgService, orgParamName: 'orgId', workspaceParamName: 'workspaceId' }),
      (req, res) => {
        res.status(200).json({
          organizationId: req.tenant?.organizationId,
          workspaceId: req.tenant?.workspaceId,
        });
      }
    );

    app.use(errorHandler());
  });

  it('allows active member to select organization via route parameter', async () => {
    const res = await request(app).get(`/api/v1/organizations/${orgA}/data`);
    expect(res.status).toBe(200);
    expect(res.body.organizationId).toBe(orgA);
    expect(res.body.role).toBe('leader');
  });

  it('allows tenant and workspace selection with X-Workspace-Id header', async () => {
    const res = await request(app)
      .get(`/api/v1/organizations/${orgA}/data`)
      .set('X-Workspace-Id', 'ws-engineering-456');

    expect(res.status).toBe(200);
    expect(res.body.organizationId).toBe(orgA);
    expect(res.body.workspaceId).toBe('ws-engineering-456');
  });

  it('rejects access to organization when membership is suspended (403)', async () => {
    const res = await request(app).get(`/api/v1/organizations/${orgB}/data`);
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('TENANT_ACCESS_DENIED');
  });

  it('CRITICAL IDOR: Rejects access to organization where user has no membership (403)', async () => {
    const res = await request(app).get('/api/v1/organizations/org-unauthorized-xyz/data');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('TENANT_ACCESS_DENIED');
    expect(res.body.error.message).toContain('not an active member');
  });

  it('rejects request when organization identifier is completely missing', async () => {
    const res = await request(app).get('/api/v1/workspaces/ws-only-no-org/data');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('TENANT_ACCESS_DENIED');
    expect(res.body.error.message).toContain('Organization or tenant context is required');
  });

  it('allows workspace route when organization is supplied via X-Tenant-Id header', async () => {
    const res = await request(app)
      .get('/api/v1/workspaces/ws-777/data')
      .set('X-Tenant-Id', orgA);

    expect(res.status).toBe(200);
    expect(res.body.organizationId).toBe(orgA);
    expect(res.body.workspaceId).toBe('ws-777');
  });
});
