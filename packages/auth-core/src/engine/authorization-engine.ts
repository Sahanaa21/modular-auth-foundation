import { PlatformRole, OrgRole } from '../types/roles.js';
import {
  Permission,
  ResourceAccessRequest,
  AuthorizationDecision,
  IAuthorizationEngine,
  PermissionMatrixConfig,
} from '../types/permissions.js';
import { createPermissionMatrixConfig } from '../config/permissions-matrix.js';

export interface AuthorizationEngineOptions {
  /** Optional custom permission matrix configuration */
  readonly matrixConfig?: PermissionMatrixConfig;
}

/**
 * Standard implementation of the Authorization Engine.
 * Enforces dual-tier role separation, tenant scoping, and fail-closed evaluation.
 */
export class AuthorizationEngine implements IAuthorizationEngine {
  private readonly matrixConfig: PermissionMatrixConfig;

  constructor(options: AuthorizationEngineOptions = {}) {
    this.matrixConfig = options.matrixConfig ?? createPermissionMatrixConfig();
  }

  /**
   * Evaluates if a platform role possesses the requested permission.
   */
  public hasPlatformPermission(role: PlatformRole | null | undefined, permission: Permission): boolean {
    if (!role) {
      return false;
    }
    const permissions = this.matrixConfig.platform[role];
    if (!permissions) {
      return false;
    }
    return permissions.includes(permission);
  }

  /**
   * Evaluates if an organization role possesses the requested permission.
   */
  public hasOrgPermission(role: OrgRole | null | undefined, permission: Permission): boolean {
    if (!role) {
      return false;
    }
    const permissions = this.matrixConfig.organization[role];
    if (!permissions) {
      return false;
    }
    return permissions.includes(permission);
  }

  /**
   * Multi-dimensional evaluation considering:
   * - Actor platform role
   * - Actor organization role within target tenant
   * - Requested action
   * - Target resource context
   *
   * Enforces fail-closed: Defaults to Deny if any parameter is ambiguous or missing.
   */
  public evaluate(
    platformRole: PlatformRole | null | undefined,
    orgRole: OrgRole | null | undefined,
    request: ResourceAccessRequest
  ): AuthorizationDecision {
    const evaluatedAt = new Date();
    const action = request.action;

    // Rule 1: Check if this is a Platform-level permission
    if (this.isPlatformScopedAction(action)) {
      if (!platformRole) {
        return {
          granted: false,
          reason: 'Access denied: Platform-level role required',
          evaluatedAt,
          requiredPermission: action,
        };
      }

      const hasPermission = this.hasPlatformPermission(platformRole, action);
      if (!hasPermission) {
        return {
          granted: false,
          reason: `Access denied: Platform role '${platformRole}' lacks permission '${action}'`,
          evaluatedAt,
          requiredPermission: action,
        };
      }

      return {
        granted: true,
        evaluatedAt,
        requiredPermission: action,
      };
    }

    // Rule 2: Tenant/Organization-level permission check
    // Tenant actions REQUIRE an organizationId context
    if (!request.organizationId) {
      return {
        granted: false,
        reason: 'Access denied: Organization context is missing for tenant-scoped operation',
        evaluatedAt,
        requiredPermission: action,
      };
    }

    // Tenant actions REQUIRE a valid active organization role
    if (!orgRole) {
      return {
        granted: false,
        reason: 'Access denied: Active organization membership required',
        evaluatedAt,
        requiredPermission: action,
      };
    }

    // Validate the organization role against the permission matrix
    const hasOrgPerm = this.hasOrgPermission(orgRole, action);
    if (!hasOrgPerm) {
      return {
        granted: false,
        reason: `Access denied: Organization role '${orgRole}' lacks permission '${action}'`,
        evaluatedAt,
        requiredPermission: action,
      };
    }

    // Rule 3: Resource Ownership / IDOR Context Checks
    if (request.resourceId && request.resourceOwnerId) {
      // If resource specifies an owner and the role is limited (e.g., guest/intern cannot edit non-owned resources)
      if (orgRole === 'guest' && action.startsWith('resource:')) {
        return {
          granted: false,
          reason: 'Access denied: Guests cannot perform mutating operations on tenant resources',
          evaluatedAt,
          requiredPermission: action,
        };
      }
    }

    // Granted organization-level permission
    return {
      granted: true,
      evaluatedAt,
      requiredPermission: action,
    };
  }

  /**
   * Determines if a permission is platform-scoped based on prefix convention or matrix mapping.
   */
  private isPlatformScopedAction(action: Permission): boolean {
    if (typeof action === 'string' && action.startsWith('platform:')) {
      return true;
    }
    // Also check if any platform role explicitly maps this permission
    return Object.values(this.matrixConfig.platform).some((perms) =>
      perms.includes(action)
    );
  }
}
