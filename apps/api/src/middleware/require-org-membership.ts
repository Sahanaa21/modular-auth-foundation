import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  IOrganizationService,
  TenantAccessError,
  AuthenticationError,
} from '@modular-auth/core';

export interface RequireTenantMembershipOptions {
  readonly orgService: IOrganizationService;
  /** Name of route parameter containing organization ID. Defaults to 'orgId' */
  readonly orgParamName?: string;
  /** Name of route parameter containing workspace ID. Defaults to 'workspaceId' */
  readonly workspaceParamName?: string;
}

export type RequireOrgMembershipOptions = RequireTenantMembershipOptions;

/**
 * Middleware that validates the user's active membership in the target organization or workspace tenant.
 *
 * Supports:
 * - Route params: `/:orgId`, `/:workspaceId`, `/:tenantId`
 * - Headers: `X-Organization-Id`, `X-Workspace-Id`, `X-Tenant-Id`
 * - Query params: `organizationId`, `workspaceId`, `tenantId`
 *
 * Hydrates `req.tenant` with verified organizationId, optional workspaceId, and membership records.
 */
export function requireTenantMembership(options: RequireTenantMembershipOptions): RequestHandler {
  const orgParam = options.orgParamName ?? 'orgId';
  const workspaceParam = options.workspaceParamName ?? 'workspaceId';

  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.auth?.user) {
        throw new AuthenticationError('Authentication required before checking organization membership');
      }

      // Extract organization/tenant ID
      const orgId =
        req.params[orgParam] ||
        req.params['tenantId'] ||
        (req.headers['x-organization-id'] as string) ||
        (req.headers['x-tenant-id'] as string) ||
        (req.query['organizationId'] as string) ||
        (req.query['tenantId'] as string);

      // Extract workspace ID if present
      const workspaceId =
        req.params[workspaceParam] ||
        (req.headers['x-workspace-id'] as string) ||
        (req.query['workspaceId'] as string) ||
        undefined;

      if (!orgId || typeof orgId !== 'string') {
        throw new TenantAccessError(
          `Organization or tenant context is required (missing :${orgParam}, X-Organization-Id, or X-Tenant-Id header)`
        );
      }

      // Verify active tenant membership in database
      const membership = await options.orgService.getMembership(req.auth.user.id, orgId);

      if (!membership || membership.status !== 'active') {
        throw new TenantAccessError('Access denied: You are not an active member of this organization');
      }

      // Attach verified tenant context
      req.tenant = {
        organizationId: orgId,
        workspaceId,
        membership,
      };

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Backward-compatible alias for requireTenantMembership.
 */
export const requireOrgMembership = requireTenantMembership;
