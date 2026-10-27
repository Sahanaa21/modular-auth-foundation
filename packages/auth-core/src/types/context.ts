import { UserIdentity, VerifiedTokenClaims } from './auth.js';
import { OrgRole, PlatformRole } from './roles.js';
import { Permission } from './permissions.js';

/**
 * The physical authenticated person / human subject, distinct from
 * any specific platform role or tenant membership.
 */
export interface AuthenticatedPerson {
  /** Unique subject identifier (e.g. Supabase auth.users UUID) */
  readonly id: string;
  /** Primary verified email address */
  readonly email: string;
  /** Optional human display name */
  readonly fullName?: string;
  /** Whether the email has been confirmed by the identity provider */
  readonly isEmailVerified: boolean;
  /** Provider-supplied profile metadata */
  readonly metadata?: Record<string, unknown>;
  /** Timestamp when the person signed up */
  readonly createdAt: Date;
}

/**
 * Tenant entity model for multi-tenant organizations.
 */
export interface TenantIdentity {
  /** Unique tenant identifier */
  readonly id: string;
  /** Human-readable tenant name */
  readonly name: string;
  /** URL-friendly slug */
  readonly slug: string;
  /** Tenant lifecycle status */
  readonly status: 'active' | 'suspended' | 'archived';
  /** Optional commercial tier or product subscription */
  readonly plan?: string;
  /** Custom tenant metadata */
  readonly metadata?: Record<string, unknown>;
  readonly createdAt: Date;
  readonly updatedAt?: Date;
}

/**
 * Organization tenant model (alias of TenantIdentity with backward compatibility).
 */
export interface Organization extends TenantIdentity {}

/**
 * Workspace model for applications partitioning tenants into distinct workspaces.
 */
export interface WorkspaceIdentity {
  /** Unique workspace identifier */
  readonly id: string;
  /** Parent organization/tenant identifier */
  readonly tenantId: string;
  /** Human-readable workspace name */
  readonly name: string;
  /** URL-friendly workspace slug */
  readonly slug: string;
  /** Status of the workspace */
  readonly status: 'active' | 'archived';
  readonly createdAt: Date;
  readonly updatedAt?: Date;
}

/**
 * Membership record associating a user identity with an organization or tenant.
 */
export interface OrganizationMembership {
  readonly id: string;
  readonly userId: string;
  readonly organizationId: string;
  readonly role: OrgRole;
  readonly status: 'active' | 'invited' | 'suspended';
  readonly createdAt: Date;
  readonly organization?: Organization;
}

/**
 * Authenticated user context attached to server requests and client state.
 */
export interface AuthContext {
  /** The validated user identity */
  readonly user: UserIdentity;
  /** The verified claims from the access token */
  readonly claims: VerifiedTokenClaims;
  /** The raw verified access token */
  readonly token: string;
  /** The authenticated person contract */
  readonly person?: AuthenticatedPerson;
}

/**
 * Alias for AuthContext adhering to the explicit naming convention in Part 5.
 */
export type AuthenticationContext = AuthContext;

/**
 * Tenant and workspace context for organization-scoped operations.
 */
export interface TenantContext {
  /** The active organization / tenant ID being operated upon */
  readonly organizationId: string;
  /** Optional workspace identifier when operating within a specific workspace */
  readonly workspaceId?: string;
  /** The validated membership of the authenticated user in this organization */
  readonly membership: OrganizationMembership;
  /** Optional workspace metadata */
  readonly workspace?: WorkspaceIdentity;
}

/**
 * Multi-dimensional authorization context combining the authenticated person,
 * platform role, tenant/workspace selection, membership, and evaluated permissions.
 */
export interface AuthorizationContext {
  /** The authenticated person performing the action */
  readonly person: AuthenticatedPerson | UserIdentity;
  /** The user's system-level platform role, if any */
  readonly platformRole?: PlatformRole | null;
  /** The active tenant context, if an organization is targeted */
  readonly tenant?: TenantContext;
  /** The active workspace context, if a workspace is targeted */
  readonly workspace?: WorkspaceIdentity;
  /** The active organization membership within the target tenant */
  readonly membership?: OrganizationMembership;
  /** The resolved, active permissions granted to the actor in this context */
  readonly permissions: readonly Permission[];
  /** Timestamp when the authorization context was assembled */
  readonly evaluatedAt: Date;
}

/**
 * Full request security context combining authentication, tenancy, and authorization.
 */
export interface SecurityContext extends AuthContext {
  /** Populated when an operation targets an organization tenant */
  readonly tenant?: TenantContext;
  /** Full authorization context when permissions have been evaluated */
  readonly authz?: AuthorizationContext;
}

/**
 * Interface for fetching and validating organization tenancy.
 */
export interface IOrganizationService {
  /**
   * Retrieves active organization memberships for a user.
   */
  getUserMemberships(userId: string): Promise<readonly OrganizationMembership[]>;

  /**
   * Validates if a user is an active member of the specified organization.
   * Returns membership if active, or null/throws if not a member.
   */
  getMembership(userId: string, organizationId: string): Promise<OrganizationMembership | null>;

  /**
   * Fetch organization details by ID.
   */
  getOrganizationById(organizationId: string): Promise<Organization | null>;

  /**
   * Optional workspace lookup for applications utilizing workspaces.
   */
  getWorkspaceById?(workspaceId: string): Promise<WorkspaceIdentity | null>;
}
