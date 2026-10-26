/**
 * Platform-level roles define system-wide administrative, operational,
 * and support capabilities across the multi-tenant platform.
 *
 * IMPORTANT: A platform role NEVER inherits or confers organization-level
 * permissions automatically unless explicitly mapped and audited.
 */
export const PlatformRoles = {
  FOUNDER: 'founder',
  DEVELOPER: 'developer',
  CLIENT_SERVICING: 'client_servicing',
  ACCOUNTS: 'accounts',
} as const;

export type PlatformRole = typeof PlatformRoles[keyof typeof PlatformRoles];

/**
 * Organization-level roles define tenant-scoped permissions within a specific
 * workspace or organization.
 *
 * IMPORTANT: An organization role NEVER grants platform-level privileges,
 * even if role names or permission verbs overlap.
 */
export const OrgRoles = {
  BUSINESS_OWNER: 'business_owner',
  LEADER: 'leader',
  MANAGER: 'manager',
  EXECUTIVE: 'executive',
  INTERN: 'intern',
  COLLABORATOR: 'collaborator',
  GUEST: 'guest',
} as const;

export type OrgRole = typeof OrgRoles[keyof typeof OrgRoles];

/**
 * Type guard for platform roles
 */
export function isPlatformRole(role: string): role is PlatformRole {
  return Object.values(PlatformRoles).includes(role as PlatformRole);
}

/**
 * Type guard for organization roles
 */
export function isOrgRole(role: string): role is OrgRole {
  return Object.values(OrgRoles).includes(role as OrgRole);
}
