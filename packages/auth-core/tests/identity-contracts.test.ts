import { describe, it, expect } from 'vitest';
import {
  AuthenticatedPerson,
  TenantIdentity,
  WorkspaceIdentity,
  OrganizationMembership,
  AuthorizationContext,
  PlatformRoles,
  OrgRoles,
  StandardPermissions,
  AALLevel,
  MFAFactor,
  MFAVerificationRequiredError,
  MFAEnrollmentRequiredError,
} from '../src/index.js';

describe('Identity & Authorization Contracts Suite', () => {
  it('instantiates and validates an AuthenticatedPerson contract', () => {
    const person: AuthenticatedPerson = {
      id: 'person-uuid-1',
      email: 'shanker@archscale.com',
      fullName: 'Shanker',
      isEmailVerified: true,
      metadata: { department: 'Engineering' },
      createdAt: new Date('2026-01-01'),
    };

    expect(person.id).toBe('person-uuid-1');
    expect(person.email).toBe('shanker@archscale.com');
    expect(person.fullName).toBe('Shanker');
    expect(person.isEmailVerified).toBe(true);
  });

  it('differentiates between TenantIdentity and WorkspaceIdentity', () => {
    const tenant: TenantIdentity = {
      id: 'tenant-100',
      name: 'ArchScale Global',
      slug: 'archscale-global',
      status: 'active',
      plan: 'enterprise',
      createdAt: new Date(),
    };

    const workspace: WorkspaceIdentity = {
      id: 'workspace-500',
      tenantId: tenant.id,
      name: 'Production Workspace',
      slug: 'prod-ws',
      status: 'active',
      createdAt: new Date(),
    };

    expect(workspace.tenantId).toBe(tenant.id);
    expect(workspace.slug).toBe('prod-ws');
    expect(tenant.status).toBe('active');
  });

  it('assembles a complete multi-dimensional AuthorizationContext', () => {
    const person: AuthenticatedPerson = {
      id: 'person-999',
      email: 'founder@archscale.com',
      isEmailVerified: true,
      createdAt: new Date(),
    };

    const membership: OrganizationMembership = {
      id: 'mem-1',
      userId: person.id,
      organizationId: 'tenant-100',
      role: OrgRoles.BUSINESS_OWNER,
      status: 'active',
      createdAt: new Date(),
    };

    const authzContext: AuthorizationContext = {
      person,
      platformRole: PlatformRoles.FOUNDER,
      tenant: {
        organizationId: 'tenant-100',
        workspaceId: 'workspace-500',
        membership,
      },
      workspace: {
        id: 'workspace-500',
        tenantId: 'tenant-100',
        name: 'Core Workspace',
        slug: 'core-ws',
        status: 'active',
        createdAt: new Date(),
      },
      membership,
      permissions: [StandardPermissions.PLATFORM_MANAGE_ALL, StandardPermissions.ORG_VIEW],
      evaluatedAt: new Date(),
    };

    expect(authzContext.platformRole).toBe('founder');
    expect(authzContext.membership?.role).toBe('business_owner');
    expect(authzContext.permissions).toContain(StandardPermissions.PLATFORM_MANAGE_ALL);
    expect(authzContext.tenant?.workspaceId).toBe('workspace-500');
  });

  it('instantiates and serializes MFA error contracts without leaking internals', () => {
    const mfaRequiredError = new MFAVerificationRequiredError('Step-up verification required', {
      currentLevel: 'aal1' as AALLevel,
      requiredLevel: 'aal2' as AALLevel,
    });

    expect(mfaRequiredError.statusCode).toBe(403);
    expect(mfaRequiredError.code).toBe('MFA_REQUIRED');
    expect(mfaRequiredError.toJSON()).toEqual({
      error: {
        code: 'MFA_REQUIRED',
        message: 'Step-up verification required',
        details: {
          currentLevel: 'aal1',
          requiredLevel: 'aal2',
        },
      },
    });

    const mfaEnrollmentError = new MFAEnrollmentRequiredError();
    expect(mfaEnrollmentError.statusCode).toBe(403);
    expect(mfaEnrollmentError.code).toBe('MFA_ENROLLMENT_REQUIRED');
  });

  it('validates MFA factor data structures', () => {
    const factor: MFAFactor = {
      id: 'factor-totp-123',
      factorType: 'totp',
      status: 'verified',
      friendlyName: 'Google Authenticator',
      createdAt: new Date(),
    };

    expect(factor.factorType).toBe('totp');
    expect(factor.status).toBe('verified');
  });
});
