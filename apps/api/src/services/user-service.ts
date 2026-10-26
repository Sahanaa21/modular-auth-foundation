import { createClient, SupabaseClient } from '@supabase/supabase-js';
import {
  PlatformRole,
  isPlatformRole,
  AuthorizationError,
} from '@modular-auth/core';

export interface IUserService {
  /**
   * Retrieves the user's authoritative profile and platform role from the database.
   */
  getUserProfile(userId: string): Promise<{ platformRole?: PlatformRole | null; email?: string } | null>;

  /**
   * Updates a user's platform role. Only executable by an authenticated superadmin or founder.
   */
  updatePlatformRole(
    actorRole: PlatformRole | null | undefined,
    targetUserId: string,
    newRole: PlatformRole | null
  ): Promise<void>;

  /**
   * Atomic one-time bootstrap to assign the first superadmin when no superadmin exists.
   * Locked permanently after the first superadmin is provisioned.
   */
  bootstrapSuperadmin(targetUserId: string): Promise<void>;
}

export interface SupabaseUserServiceOptions {
  readonly supabaseUrl: string;
  readonly serviceRoleKey: string;
}

/**
 * Production implementation querying Supabase PostgreSQL via the service-role client.
 */
export class SupabaseUserService implements IUserService {
  private readonly supabase: SupabaseClient;

  constructor(options: SupabaseUserServiceOptions) {
    this.supabase = createClient(options.supabaseUrl, options.serviceRoleKey, {
      auth: { persistSession: false },
    });
  }

  public async getUserProfile(userId: string): Promise<{ platformRole?: PlatformRole | null; email?: string } | null> {
    const { data, error } = await this.supabase
      .from('users')
      .select('id, email, platform_role')
      .eq('id', userId)
      .maybeSingle();

    if (error || !data) {
      return null;
    }

    const platformRole = data.platform_role && isPlatformRole(data.platform_role)
      ? (data.platform_role as PlatformRole)
      : null;

    return {
      platformRole,
      email: data.email,
    };
  }

  public async updatePlatformRole(
    actorRole: PlatformRole | null | undefined,
    targetUserId: string,
    newRole: PlatformRole | null
  ): Promise<void> {
    // Only superadmin or founder can assign/update platform roles
    if (actorRole !== 'superadmin' && actorRole !== 'founder') {
      throw new AuthorizationError('Only Super Administrators or Founders can assign platform roles');
    }

    if (newRole && !isPlatformRole(newRole)) {
      throw new Error(`Invalid platform role '${newRole}'`);
    }

    const { error } = await this.supabase
      .from('users')
      .update({ platform_role: newRole, updated_at: new Date().toISOString() })
      .eq('id', targetUserId);

    if (error) {
      throw new Error(`Database error updating platform role: ${error.message}`);
    }
  }

  public async bootstrapSuperadmin(targetUserId: string): Promise<void> {
    const { error } = await this.supabase.rpc('bootstrap_initial_superadmin', {
      target_user_id: targetUserId,
    });

    if (error) {
      if (error.message.includes('Bootstrap locked')) {
        throw new AuthorizationError('Bootstrap locked: An initial Super Administrator or Founder already exists.');
      }
      throw new Error(`Database error bootstrapping initial superadmin: ${error.message}`);
    }
  }
}

/**
 * In-memory user service for hermetic testing and local demonstration without external credentials.
 */
export class InMemoryUserService implements IUserService {
  private readonly users = new Map<string, { email: string; platformRole: PlatformRole | null }>();
  private bootstrapLock = false;

  public setUser(userId: string, email: string, platformRole: PlatformRole | null = null): void {
    this.users.set(userId, { email, platformRole });
  }

  public async getUserProfile(userId: string): Promise<{ platformRole?: PlatformRole | null; email?: string } | null> {
    const record = this.users.get(userId);
    if (!record) {
      return null;
    }
    return {
      platformRole: record.platformRole,
      email: record.email,
    };
  }

  public async updatePlatformRole(
    actorRole: PlatformRole | null | undefined,
    targetUserId: string,
    newRole: PlatformRole | null
  ): Promise<void> {
    if (actorRole !== 'superadmin' && actorRole !== 'founder') {
      throw new AuthorizationError('Only Super Administrators or Founders can assign platform roles');
    }

    const record = this.users.get(targetUserId);
    if (!record) {
      throw new Error(`User '${targetUserId}' not found`);
    }

    this.users.set(targetUserId, {
      ...record,
      platformRole: newRole,
    });
  }

  public async bootstrapSuperadmin(targetUserId: string): Promise<void> {
    // Simulate atomic concurrency lock
    while (this.bootstrapLock) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    this.bootstrapLock = true;

    try {
      const hasSuperadmin = Array.from(this.users.values()).some(
        (u) => u.platformRole === 'superadmin' || u.platformRole === 'founder'
      );

      if (hasSuperadmin) {
        throw new AuthorizationError('Bootstrap locked: An initial Super Administrator or Founder already exists.');
      }

      const record = this.users.get(targetUserId);
      if (!record) {
        throw new Error(`Target user ID '${targetUserId}' does not exist in users store.`);
      }

      this.users.set(targetUserId, {
        ...record,
        platformRole: 'superadmin',
      });
    } finally {
      this.bootstrapLock = false;
    }
  }

  public clear(): void {
    this.users.clear();
    this.bootstrapLock = false;
  }
}
