import { UserIdentity, VerifiedTokenClaims } from './auth.js';
import { OrgRole } from './roles.js';

/**
 * Organization tenant model.
 */
export interface Organization {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly status: 'active' | 'suspended' | 'archived';
  readonly createdAt: Date;
  readonly updatedAt?: Date;
}

/**
 * Membership record associating a user identity with an organization tenant.
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
}

/**
 * Tenant context for organization-scoped operations.
 */
export interface TenantContext {
  /** The active organization ID being operated upon */
  readonly organizationId: string;
  /** The validated membership of the authenticated user in this organization */
  readonly membership: OrganizationMembership;
}

/**
 * Full request security context combining identity, tenancy, and permissions.
 */
export interface SecurityContext extends AuthContext {
  /** Populated when an operation targets an organization tenant */
  readonly tenant?: TenantContext;
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
}
