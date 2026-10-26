import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  IOrganizationService,
  TenantAccessError,
  AuthenticationError,
} from '@modular-auth/core';

export interface RequireOrgMembershipOptions {
  readonly orgService: IOrganizationService;
  /** Name of route parameter containing organization ID. Defaults to 'orgId' */
  readonly orgParamName?: string;
}

/**
 * Middleware that validates the user's active membership in the target organization tenant.
 * Hydrates req.tenant with verified organization and membership records.
 */
export function requireOrgMembership(options: RequireOrgMembershipOptions): RequestHandler {
  const paramName = options.orgParamName ?? 'orgId';

  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.auth?.user) {
        throw new AuthenticationError('Authentication required before checking organization membership');
      }

      // Extract organization ID from route params, custom header, or query
      const orgId =
        req.params[paramName] ||
        (req.headers['x-organization-id'] as string) ||
        (req.query['organizationId'] as string);

      if (!orgId || typeof orgId !== 'string') {
        throw new TenantAccessError(`Organization ID context is required (missing :${paramName} or X-Organization-Id header)`);
      }

      // Verify active tenant membership in database
      const membership = await options.orgService.getMembership(req.auth.user.id, orgId);

      if (!membership || membership.status !== 'active') {
        throw new TenantAccessError('Access denied: You are not an active member of this organization');
      }

      // Attach verified tenant context
      req.tenant = {
        organizationId: orgId,
        membership,
      };

      next();
    } catch (error) {
      next(error);
    }
  };
}
