import { describe, it, expect, beforeEach } from 'vitest';
import {
  AuthorizationEngine,
  PlatformRoles,
  OrgRoles,
  StandardPermissions,
  createPermissionMatrixConfig,
  isPlatformRole,
  isOrgRole,
  AuthenticationError,
  AuthorizationError,
  TenantAccessError,
  ResourceAccessError,
} from '../src/index.js';

describe('AuthorizationEngine', () => {
  let engine: AuthorizationEngine;

  beforeEach(() => {
    engine = new AuthorizationEngine();
  });

  describe('Type Guards', () => {
    it('correctly validates platform roles', () => {
      expect(isPlatformRole('superadmin')).toBe(true);
      expect(isPlatformRole('admin')).toBe(true);
      expect(isPlatformRole('founder')).toBe(true);
      expect(isPlatformRole('developer')).toBe(true);
      expect(isPlatformRole('client_servicing')).toBe(true);
      expect(isPlatformRole('accounts')).toBe(true);
      expect(isPlatformRole('business_owner')).toBe(false);
      expect(isPlatformRole('unknown_role')).toBe(false);
    });

    it('correctly validates organization roles', () => {
      expect(isOrgRole('business_owner')).toBe(true);
      expect(isOrgRole('leader')).toBe(true);
      expect(isOrgRole('manager')).toBe(true);
      expect(isOrgRole('executive')).toBe(true);
      expect(isOrgRole('intern')).toBe(true);
      expect(isOrgRole('collaborator')).toBe(true);
      expect(isOrgRole('guest')).toBe(true);
      expect(isOrgRole('founder')).toBe(false);
      expect(isOrgRole('superadmin')).toBe(false);
    });
  });

  describe('Platform Role Permissions', () => {
    it('grants superadmin full platform access', () => {
      expect(engine.hasPlatformPermission(PlatformRoles.SUPER_ADMIN, StandardPermissions.PLATFORM_MANAGE_ALL)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.SUPER_ADMIN, StandardPermissions.PLATFORM_MANAGE_USERS)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.SUPER_ADMIN, StandardPermissions.PLATFORM_VIEW_SYSTEM)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.SUPER_ADMIN, StandardPermissions.PLATFORM_BILLING_AUDIT)).toBe(true);
    });

    it('grants admin operational platform permissions but restricts total platform management', () => {
      expect(engine.hasPlatformPermission(PlatformRoles.ADMIN, StandardPermissions.PLATFORM_MANAGE_USERS)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.ADMIN, StandardPermissions.PLATFORM_VIEW_SYSTEM)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.ADMIN, StandardPermissions.PLATFORM_VIEW_METRICS)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.ADMIN, StandardPermissions.PLATFORM_MANAGE_ALL)).toBe(false);
    });

    it('grants founder full platform access', () => {
      expect(engine.hasPlatformPermission(PlatformRoles.FOUNDER, StandardPermissions.PLATFORM_MANAGE_ALL)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.FOUNDER, StandardPermissions.PLATFORM_MANAGE_USERS)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.FOUNDER, StandardPermissions.PLATFORM_VIEW_SYSTEM)).toBe(true);
    });

    it('restricts developer from user management but allows system metrics', () => {
      expect(engine.hasPlatformPermission(PlatformRoles.DEVELOPER, StandardPermissions.PLATFORM_VIEW_SYSTEM)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.DEVELOPER, StandardPermissions.PLATFORM_VIEW_METRICS)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.DEVELOPER, StandardPermissions.PLATFORM_MANAGE_USERS)).toBe(false);
    });

    it('grants accounts billing audit permissions', () => {
      expect(engine.hasPlatformPermission(PlatformRoles.ACCOUNTS, StandardPermissions.PLATFORM_BILLING_AUDIT)).toBe(true);
      expect(engine.hasPlatformPermission(PlatformRoles.ACCOUNTS, StandardPermissions.PLATFORM_MANAGE_ALL)).toBe(false);
    });

    it('fails closed when platform role is null or undefined', () => {
      expect(engine.hasPlatformPermission(null, StandardPermissions.PLATFORM_VIEW_SYSTEM)).toBe(false);
      expect(engine.hasPlatformPermission(undefined, StandardPermissions.PLATFORM_VIEW_SYSTEM)).toBe(false);
    });

    it('CRITICAL: Organization roles NEVER grant platform permissions', () => {
      // Even the highest org role (business_owner) must not gain platform permissions
      const decision = engine.evaluate(
        null, // No platform role
        OrgRoles.BUSINESS_OWNER, // Has highest org role
        {
          action: StandardPermissions.PLATFORM_MANAGE_ALL,
          resourceType: 'platform',
        }
      );

      expect(decision.granted).toBe(false);
      expect(decision.reason).toContain('Platform-level role required');
    });
  });

  describe('Organization Role Permissions', () => {
    const orgId = 'org-uuid-1234';

    it('grants business_owner full organization permissions', () => {
      expect(engine.hasOrgPermission(OrgRoles.BUSINESS_OWNER, StandardPermissions.ORG_DELETE)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.BUSINESS_OWNER, StandardPermissions.MEMBER_INVITE)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.BUSINESS_OWNER, StandardPermissions.RESOURCE_DELETE)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.BUSINESS_OWNER, StandardPermissions.BILLING_MANAGE)).toBe(true);
    });

    it('allows leader to invite and manage resources but not delete organization', () => {
      expect(engine.hasOrgPermission(OrgRoles.LEADER, StandardPermissions.MEMBER_INVITE)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.LEADER, StandardPermissions.RESOURCE_CREATE)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.LEADER, StandardPermissions.ORG_DELETE)).toBe(false);
    });

    it('limits intern to read-only access', () => {
      expect(engine.hasOrgPermission(OrgRoles.INTERN, StandardPermissions.RESOURCE_READ)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.INTERN, StandardPermissions.MEMBER_LIST)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.INTERN, StandardPermissions.RESOURCE_CREATE)).toBe(false);
      expect(engine.hasOrgPermission(OrgRoles.INTERN, StandardPermissions.RESOURCE_DELETE)).toBe(false);
      expect(engine.hasOrgPermission(OrgRoles.INTERN, StandardPermissions.MEMBER_INVITE)).toBe(false);
    });

    it('limits guest to view and read permissions only', () => {
      expect(engine.hasOrgPermission(OrgRoles.GUEST, StandardPermissions.ORG_VIEW)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.GUEST, StandardPermissions.RESOURCE_READ)).toBe(true);
      expect(engine.hasOrgPermission(OrgRoles.GUEST, StandardPermissions.RESOURCE_CREATE)).toBe(false);
      expect(engine.hasOrgPermission(OrgRoles.GUEST, StandardPermissions.MEMBER_LIST)).toBe(false);
    });

    it('fails closed when org role is null or undefined', () => {
      expect(engine.hasOrgPermission(null, StandardPermissions.RESOURCE_READ)).toBe(false);
      expect(engine.hasOrgPermission(undefined, StandardPermissions.RESOURCE_READ)).toBe(false);
    });

    it('rejects organization action when organizationId is missing', () => {
      const decision = engine.evaluate(
        null,
        OrgRoles.LEADER,
        {
          action: StandardPermissions.RESOURCE_READ,
          resourceType: 'project',
          // organizationId intentionally omitted!
        }
      );

      expect(decision.granted).toBe(false);
      expect(decision.reason).toContain('Organization context is missing');
    });

    it('rejects organization action when actor is not an org member', () => {
      const decision = engine.evaluate(
        PlatformRoles.DEVELOPER, // User is platform developer
        null, // But NOT a member of this tenant org
        {
          action: StandardPermissions.RESOURCE_READ,
          resourceType: 'project',
          organizationId: orgId,
        }
      );

      expect(decision.granted).toBe(false);
      expect(decision.reason).toContain('Active organization membership required');
    });

    it('allows valid member with proper permission to access resource', () => {
      const decision = engine.evaluate(
        null,
        OrgRoles.MANAGER,
        {
          action: StandardPermissions.RESOURCE_CREATE,
          resourceType: 'project',
          organizationId: orgId,
        }
      );

      expect(decision.granted).toBe(true);
      expect(decision.requiredPermission).toBe(StandardPermissions.RESOURCE_CREATE);
    });
  });

  describe('Custom Matrix Configuration', () => {
    it('supports customizing permission matrices', () => {
      const customConfig = createPermissionMatrixConfig({
        organization: {
          [OrgRoles.INTERN]: [StandardPermissions.RESOURCE_READ, StandardPermissions.RESOURCE_CREATE],
        },
      });

      const customEngine = new AuthorizationEngine({ matrixConfig: customConfig });

      expect(customEngine.hasOrgPermission(OrgRoles.INTERN, StandardPermissions.RESOURCE_CREATE)).toBe(true);
    });
  });

  describe('Error Hierarchy Serialization', () => {
    it('serializes AuthenticationError with HTTP 401 and sanitized JSON', () => {
      const err = new AuthenticationError('Token expired');
      expect(err.statusCode).toBe(401);
      expect(err.code).toBe('UNAUTHENTICATED');
      expect(err.toJSON()).toEqual({
        error: {
          code: 'UNAUTHENTICATED',
          message: 'Token expired',
        },
      });
    });

    it('serializes AuthorizationError with HTTP 403', () => {
      const err = new AuthorizationError('Insufficient permissions');
      expect(err.statusCode).toBe(403);
      expect(err.code).toBe('FORBIDDEN');
    });

    it('serializes TenantAccessError with HTTP 403', () => {
      const err = new TenantAccessError('Membership suspended');
      expect(err.statusCode).toBe(403);
      expect(err.code).toBe('TENANT_ACCESS_DENIED');
    });

    it('serializes ResourceAccessError with customizable status code', () => {
      const err = new ResourceAccessError('Resource not found in tenant', 404);
      expect(err.statusCode).toBe(404);
      expect(err.code).toBe('RESOURCE_ACCESS_DENIED');
    });
  });
});
