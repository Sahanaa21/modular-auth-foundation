import { PlatformRole, OrgRole } from './roles.js';

/**
 * Proposed permission action verbs.
 * Permissions are formatted as `<domain>:<action>`.
 */
export const StandardPermissions = {
  // Platform permissions
  PLATFORM_MANAGE_ALL: 'platform:manage_all',
  PLATFORM_VIEW_SYSTEM: 'platform:view_system',
  PLATFORM_MANAGE_USERS: 'platform:manage_users',
  PLATFORM_VIEW_METRICS: 'platform:view_metrics',
  PLATFORM_BILLING_AUDIT: 'platform:billing_audit',
  PLATFORM_SUPPORT_ACCESS: 'platform:support_access',

  // Organization administration permissions
  ORG_VIEW: 'org:view',
  ORG_UPDATE: 'org:update',
  ORG_DELETE: 'org:delete',
  ORG_TRANSFER_OWNERSHIP: 'org:transfer_ownership',

  // Member management permissions
  MEMBER_LIST: 'member:list',
  MEMBER_INVITE: 'member:invite',
  MEMBER_UPDATE_ROLE: 'member:update_role',
  MEMBER_REMOVE: 'member:remove',

  // Resource / Project permissions (tenant-scoped)
  RESOURCE_CREATE: 'resource:create',
  RESOURCE_READ: 'resource:read',
  RESOURCE_UPDATE: 'resource:update',
  RESOURCE_DELETE: 'resource:delete',

  // Billing and financial permissions
  BILLING_VIEW: 'billing:view',
  BILLING_MANAGE: 'billing:manage',

  // Audit and compliance permissions
  AUDIT_LOG_VIEW: 'audit_log:view',
} as const;

export type Permission = typeof StandardPermissions[keyof typeof StandardPermissions] | (string & {});

/**
 * Configurable Role-to-Permissions Mapping Matrices.
 * Allows applications to override or extend permissions at initialization time.
 */
export type PlatformPermissionMatrix = Record<PlatformRole, readonly Permission[]>;
export type OrgPermissionMatrix = Record<OrgRole, readonly Permission[]>;

export interface PermissionMatrixConfig {
  platform: PlatformPermissionMatrix;
  organization: OrgPermissionMatrix;
}

/**
 * Resource-level authorization request parameters.
 */
export interface ResourceAccessRequest {
  /** The action being attempted */
  readonly action: Permission;
  /** The target resource category (e.g. 'organization', 'project', 'billing') */
  readonly resourceType: string;
  /** Organization ID context for tenant-scoped operations */
  readonly organizationId?: string;
  /** Specific ID of the resource instance being accessed (to prevent IDOR) */
  readonly resourceId?: string;
  /** Optional resource owner ID to support ownership-based rules */
  readonly resourceOwnerId?: string;
}

/**
 * Result of an authorization decision.
 */
export interface AuthorizationDecision {
  readonly granted: boolean;
  readonly reason?: string;
  readonly evaluatedAt: Date;
  readonly requiredPermission: Permission;
}

/**
 * Abstract interface for evaluating permissions.
 */
export interface IAuthorizationEngine {
  /**
   * Check if a user's platform role grants the requested permission.
   */
  hasPlatformPermission(role: PlatformRole | null | undefined, permission: Permission): boolean;

  /**
   * Check if a user's organization role grants the requested permission.
   */
  hasOrgPermission(role: OrgRole | null | undefined, permission: Permission): boolean;

  /**
   * Evaluate a full resource access request against the provided context.
   */
  evaluate(
    platformRole: PlatformRole | null | undefined,
    orgRole: OrgRole | null | undefined,
    request: ResourceAccessRequest
  ): AuthorizationDecision;
}
