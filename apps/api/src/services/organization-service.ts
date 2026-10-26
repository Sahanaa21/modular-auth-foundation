import { createClient, SupabaseClient } from '@supabase/supabase-js';
import {
  IOrganizationService,
  OrganizationMembership,
  Organization,
  OrgRole,
} from '@modular-auth/core';

export interface SupabaseOrganizationServiceOptions {
  readonly supabaseUrl: string;
  readonly serviceRoleKey?: string;
  readonly supabaseClient?: SupabaseClient;
}

/**
 * Production implementation of IOrganizationService querying Supabase PostgreSQL.
 */
export class SupabaseOrganizationService implements IOrganizationService {
  private readonly supabase?: SupabaseClient;

  constructor(options: SupabaseOrganizationServiceOptions) {
    if (options.supabaseClient) {
      this.supabase = options.supabaseClient;
    } else if (options.serviceRoleKey) {
      this.supabase = createClient(options.supabaseUrl, options.serviceRoleKey, {
        auth: { persistSession: false },
      });
    }
  }

  public async getUserMemberships(userId: string): Promise<readonly OrganizationMembership[]> {
    if (!this.supabase) {
      return [];
    }

    const { data, error } = await this.supabase
      .from('organization_memberships')
      .select(`
        id,
        user_id,
        organization_id,
        role,
        status,
        created_at,
        organizations (
          id,
          name,
          slug,
          status,
          created_at
        )
      `)
      .eq('user_id', userId)
      .eq('status', 'active');

    if (error || !data) {
      return [];
    }

    return data.map((row: any) => ({
      id: row.id,
      userId: row.user_id,
      organizationId: row.organization_id,
      role: row.role as OrgRole,
      status: row.status,
      createdAt: new Date(row.created_at),
      organization: row.organizations ? {
        id: row.organizations.id,
        name: row.organizations.name,
        slug: row.organizations.slug,
        status: row.organizations.status,
        createdAt: new Date(row.organizations.created_at),
      } : undefined,
    }));
  }

  public async getMembership(userId: string, organizationId: string): Promise<OrganizationMembership | null> {
    if (!this.supabase) {
      return null;
    }

    const { data, error } = await this.supabase
      .from('organization_memberships')
      .select('id, user_id, organization_id, role, status, created_at')
      .eq('user_id', userId)
      .eq('organization_id', organizationId)
      .maybeSingle();

    if (error || !data) {
      return null;
    }

    return {
      id: data.id,
      userId: data.user_id,
      organizationId: data.organization_id,
      role: data.role as OrgRole,
      status: data.status,
      createdAt: new Date(data.created_at),
    };
  }

  public async getOrganizationById(organizationId: string): Promise<Organization | null> {
    if (!this.supabase) {
      return null;
    }

    const { data, error } = await this.supabase
      .from('organizations')
      .select('id, name, slug, status, created_at')
      .eq('id', organizationId)
      .maybeSingle();

    if (error || !data) {
      return null;
    }

    return {
      id: data.id,
      name: data.name,
      slug: data.slug,
      status: data.status,
      createdAt: new Date(data.created_at),
    };
  }
}

/**
 * In-memory organization service for automated testing and offline development.
 */
export class InMemoryOrganizationService implements IOrganizationService {
  private readonly organizations = new Map<string, Organization>();
  private readonly memberships = new Map<string, OrganizationMembership>();

  public setOrganization(org: Organization): void {
    this.organizations.set(org.id, org);
  }

  public setMembership(membership: OrganizationMembership): void {
    const key = `${membership.userId}:${membership.organizationId}`;
    this.memberships.set(key, membership);
  }

  public async getUserMemberships(userId: string): Promise<readonly OrganizationMembership[]> {
    return Array.from(this.memberships.values())
      .filter((m) => m.userId === userId && m.status === 'active')
      .map((m) => ({
        ...m,
        organization: this.organizations.get(m.organizationId),
      }));
  }

  public async getMembership(userId: string, organizationId: string): Promise<OrganizationMembership | null> {
    const key = `${userId}:${organizationId}`;
    return this.memberships.get(key) ?? null;
  }

  public async getOrganizationById(organizationId: string): Promise<Organization | null> {
    return this.organizations.get(organizationId) ?? null;
  }

  public clear(): void {
    this.organizations.clear();
    this.memberships.clear();
  }
}
