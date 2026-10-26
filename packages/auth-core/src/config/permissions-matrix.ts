import { PlatformRoles, PlatformRole, OrgRoles, OrgRole } from '../types/roles.js';
import {
  StandardPermissions,
  Permission,
  PlatformPermissionMatrix,
  OrgPermissionMatrix,
  PermissionMatrixConfig,
} from '../types/permissions.js';

/**
 * Default proposed platform role permissions.
 * Platform roles have zero access to organization resources unless explicitly audited.
 */
export const DEFAULT_PLATFORM_PERMISSIONS: PlatformPermissionMatrix = {
  [PlatformRoles.FOUNDER]: [
    StandardPermissions.PLATFORM_MANAGE_ALL,
    StandardPermissions.PLATFORM_VIEW_SYSTEM,
    StandardPermissions.PLATFORM_MANAGE_USERS,
    StandardPermissions.PLATFORM_VIEW_METRICS,
    StandardPermissions.PLATFORM_BILLING_AUDIT,
    StandardPermissions.PLATFORM_SUPPORT_ACCESS,
    StandardPermissions.AUDIT_LOG_VIEW,
  ],
  [PlatformRoles.DEVELOPER]: [
    StandardPermissions.PLATFORM_VIEW_SYSTEM,
    StandardPermissions.PLATFORM_VIEW_METRICS,
    StandardPermissions.PLATFORM_SUPPORT_ACCESS,
  ],
  [PlatformRoles.CLIENT_SERVICING]: [
    StandardPermissions.PLATFORM_VIEW_METRICS,
    StandardPermissions.PLATFORM_SUPPORT_ACCESS,
  ],
  [PlatformRoles.ACCOUNTS]: [
    StandardPermissions.PLATFORM_BILLING_AUDIT,
    StandardPermissions.PLATFORM_VIEW_METRICS,
  ],
};

/**
 * Default proposed organization role permissions.
 * Scoped strictly to the tenant organization.
 */
export const DEFAULT_ORG_PERMISSIONS: OrgPermissionMatrix = {
  [OrgRoles.BUSINESS_OWNER]: [
    StandardPermissions.ORG_VIEW,
    StandardPermissions.ORG_UPDATE,
    StandardPermissions.ORG_DELETE,
    StandardPermissions.ORG_TRANSFER_OWNERSHIP,
    StandardPermissions.MEMBER_LIST,
    StandardPermissions.MEMBER_INVITE,
    StandardPermissions.MEMBER_UPDATE_ROLE,
    StandardPermissions.MEMBER_REMOVE,
    StandardPermissions.RESOURCE_CREATE,
    StandardPermissions.RESOURCE_READ,
    StandardPermissions.RESOURCE_UPDATE,
    StandardPermissions.RESOURCE_DELETE,
    StandardPermissions.BILLING_VIEW,
    StandardPermissions.BILLING_MANAGE,
    StandardPermissions.AUDIT_LOG_VIEW,
  ],
  [OrgRoles.LEADER]: [
    StandardPermissions.ORG_VIEW,
    StandardPermissions.ORG_UPDATE,
    StandardPermissions.MEMBER_LIST,
    StandardPermissions.MEMBER_INVITE,
    StandardPermissions.MEMBER_UPDATE_ROLE,
    StandardPermissions.RESOURCE_CREATE,
    StandardPermissions.RESOURCE_READ,
    StandardPermissions.RESOURCE_UPDATE,
    StandardPermissions.RESOURCE_DELETE,
    StandardPermissions.BILLING_VIEW,
    StandardPermissions.AUDIT_LOG_VIEW,
  ],
  [OrgRoles.MANAGER]: [
    StandardPermissions.ORG_VIEW,
    StandardPermissions.MEMBER_LIST,
    StandardPermissions.MEMBER_INVITE,
    StandardPermissions.RESOURCE_CREATE,
    StandardPermissions.RESOURCE_READ,
    StandardPermissions.RESOURCE_UPDATE,
    StandardPermissions.RESOURCE_DELETE,
    StandardPermissions.AUDIT_LOG_VIEW,
  ],
  [OrgRoles.EXECUTIVE]: [
    StandardPermissions.ORG_VIEW,
    StandardPermissions.MEMBER_LIST,
    StandardPermissions.RESOURCE_CREATE,
    StandardPermissions.RESOURCE_READ,
    StandardPermissions.RESOURCE_UPDATE,
  ],
  [OrgRoles.INTERN]: [
    StandardPermissions.ORG_VIEW,
    StandardPermissions.MEMBER_LIST,
    StandardPermissions.RESOURCE_READ,
  ],
  [OrgRoles.COLLABORATOR]: [
    StandardPermissions.ORG_VIEW,
    StandardPermissions.RESOURCE_CREATE,
    StandardPermissions.RESOURCE_READ,
    StandardPermissions.RESOURCE_UPDATE,
  ],
  [OrgRoles.GUEST]: [
    StandardPermissions.ORG_VIEW,
    StandardPermissions.RESOURCE_READ,
  ],
};

/**
 * Constructs a configurable permission matrix allowing consumer applications
 * to customize or extend role mappings.
 */
export function createPermissionMatrixConfig(
  customOverrides?: Partial<{
    platform: Partial<Record<PlatformRole, readonly Permission[]>>;
    organization: Partial<Record<OrgRole, readonly Permission[]>>;
  }>
): PermissionMatrixConfig {
  return {
    platform: {
      ...DEFAULT_PLATFORM_PERMISSIONS,
      ...(customOverrides?.platform ?? {}),
    },
    organization: {
      ...DEFAULT_ORG_PERMISSIONS,
      ...(customOverrides?.organization ?? {}),
    },
  };
}
