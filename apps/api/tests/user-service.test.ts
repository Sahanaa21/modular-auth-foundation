import { describe, it, expect, vi } from 'vitest';
import { SupabaseUserService } from '../src/services/user-service.js';
import { AuthorizationError, NotFoundError, PlatformRoles, ConfigurationError } from '@modular-auth/core';
import { SupabaseClient } from '@supabase/supabase-js';

function createMockSupabaseClient(handlers: {
  fromUsersSelect?: () => Promise<{ data: any; error: any }>;
  fromUsersUpdate?: () => Promise<{ data: any; error: any }>;
  rpc?: (name: string, params: any) => Promise<{ data: any; error: any }>;
}): SupabaseClient {
  return {
    from: vi.fn((table: string) => {
      if (table === 'users') {
        return {
          select: vi.fn(() => ({
            eq: vi.fn(() => ({
              maybeSingle: vi.fn(async () => {
                if (handlers.fromUsersSelect) {
                  return handlers.fromUsersSelect();
                }
                return { data: null, error: null };
              }),
            })),
          })),
          update: vi.fn(() => ({
            eq: vi.fn(() => ({
              select: vi.fn(() => ({
                maybeSingle: vi.fn(async () => {
                  if (handlers.fromUsersUpdate) {
                    return handlers.fromUsersUpdate();
                  }
                  return { data: { id: 'target-user-002', platform_role: 'admin' }, error: null };
                }),
              })),
            })),
          })),
        };
      }
      throw new Error(`Unexpected table ${table}`);
    }),
    rpc: vi.fn(async (name: string, params: any) => {
      if (handlers.rpc) {
        return handlers.rpc(name, params);
      }
      return { data: null, error: null };
    }),
  } as unknown as SupabaseClient;
}

describe('SupabaseUserService Suite', () => {
  const supabaseUrl = 'https://vsllykwuqqmbitxvpuod.supabase.co';
  const serviceRoleKey = 'test-service-role-key';

  describe('getUserProfile', () => {
    it('returns the user profile and platform role when user row exists in public.users', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersSelect: async () => ({
          data: {
            id: 'd6d1bbef-e141-4138-ac74-987070d05527',
            email: 'superadmin.modularauth@gmail.com',
            platform_role: 'superadmin',
          },
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      const profile = await userService.getUserProfile('d6d1bbef-e141-4138-ac74-987070d05527');

      expect(profile).not.toBeNull();
      expect(profile?.platformRole).toBe(PlatformRoles.SUPER_ADMIN);
      expect(profile?.email).toBe('superadmin.modularauth@gmail.com');
    });

    it('returns null platformRole when user row exists but platform_role is null', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersSelect: async () => ({
          data: {
            id: 'target-uuid-002',
            email: 'admin.modularauth@gmail.com',
            platform_role: null,
          },
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      const profile = await userService.getUserProfile('target-uuid-002');
      expect(profile).not.toBeNull();
      expect(profile?.platformRole).toBeNull();
      expect(profile?.email).toBe('admin.modularauth@gmail.com');
    });

    it('returns null when user record does not exist in public.users', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersSelect: async () => ({
          data: null,
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      const profile = await userService.getUserProfile('non-existent-uuid');
      expect(profile).toBeNull();
    });

    it('throws a descriptive error when database query fails (e.g. Invalid API key)', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersSelect: async () => ({
          data: null,
          error: {
            message: 'Invalid API key',
            hint: 'Double check your Supabase anon or service_role API key.',
            code: 'PGRST301',
          },
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.getUserProfile('d6d1bbef-e141-4138-ac74-987070d05527')
      ).rejects.toThrow(/Database error resolving user profile: Invalid API key/);
    });

    it('throws ConfigurationError when Supabase client is not initialized', async () => {
      const unconfiguredService = new SupabaseUserService({
        supabaseUrl,
      });

      await expect(
        unconfiguredService.getUserProfile('d6d1bbef-e141-4138-ac74-987070d05527')
      ).rejects.toThrow(ConfigurationError);
    });

    it('normalizes platform_role with whitespace, uppercase, or super_admin alias', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersSelect: async () => ({
          data: {
            id: 'd6d1bbef-e141-4138-ac74-987070d05527',
            email: 'superadmin.modularauth@gmail.com',
            platform_role: 'SuperAdmin ',
          },
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      const profile = await userService.getUserProfile('d6d1bbef-e141-4138-ac74-987070d05527');
      expect(profile?.platformRole).toBe('superadmin');
    });

    it('maps super_admin alias to canonical superadmin role', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersSelect: async () => ({
          data: {
            id: 'd6d1bbef-e141-4138-ac74-987070d05527',
            email: 'superadmin.modularauth@gmail.com',
            platform_role: 'super_admin',
          },
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      const profile = await userService.getUserProfile('d6d1bbef-e141-4138-ac74-987070d05527');
      expect(profile?.platformRole).toBe('superadmin');
    });
  });

  describe('updatePlatformRole', () => {
    it('allows superadmin actor to assign admin role', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersUpdate: async () => ({
          data: { id: 'target-user-002', platform_role: 'admin' },
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      const result = await userService.updatePlatformRole(
        PlatformRoles.SUPER_ADMIN,
        'target-user-002',
        PlatformRoles.ADMIN
      );

      expect(result).toEqual({
        targetUserId: 'target-user-002',
        platformRole: PlatformRoles.ADMIN,
      });
    });

    it('allows founder actor to assign roles', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersUpdate: async () => ({
          data: { id: 'target-user-002', platform_role: 'developer' },
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      const result = await userService.updatePlatformRole(
        PlatformRoles.FOUNDER,
        'target-user-002',
        PlatformRoles.DEVELOPER
      );

      expect(result).toEqual({
        targetUserId: 'target-user-002',
        platformRole: PlatformRoles.DEVELOPER,
      });
    });

    it('throws NotFoundError when target user record does not exist', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersUpdate: async () => ({
          data: null,
          error: null,
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.updatePlatformRole(
          PlatformRoles.SUPER_ADMIN,
          'missing-user-999',
          PlatformRoles.ADMIN
        )
      ).rejects.toThrow(NotFoundError);
    });

    it('rejects ordinary admin actor from assigning platform roles', async () => {
      const mockClient = createMockSupabaseClient({});

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.updatePlatformRole(
          PlatformRoles.ADMIN,
          'target-user-002',
          PlatformRoles.SUPER_ADMIN
        )
      ).rejects.toThrow(AuthorizationError);
    });

    it('rejects unauthenticated or role-less actor from assigning platform roles', async () => {
      const mockClient = createMockSupabaseClient({});

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.updatePlatformRole(
          null,
          'target-user-002',
          PlatformRoles.ADMIN
        )
      ).rejects.toThrow(AuthorizationError);
    });

    it('rejects invalid platform role strings', async () => {
      const mockClient = createMockSupabaseClient({});

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.updatePlatformRole(
          PlatformRoles.SUPER_ADMIN,
          'target-user-002',
          'root_god_mode' as any
        )
      ).rejects.toThrow(/Invalid platform role 'root_god_mode'/);
    });

    it('throws error when database update query fails', async () => {
      const mockClient = createMockSupabaseClient({
        fromUsersUpdate: async () => ({
          data: null,
          error: { message: 'Database connection terminated' },
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.updatePlatformRole(
          PlatformRoles.SUPER_ADMIN,
          'target-user-002',
          PlatformRoles.ADMIN
        )
      ).rejects.toThrow(/Database error updating platform role: Database connection terminated/);
    });

    it('throws ConfigurationError when client is not initialized and serviceRoleKey is missing', async () => {
      const unconfiguredService = new SupabaseUserService({
        supabaseUrl,
      });

      await expect(
        unconfiguredService.updatePlatformRole(
          PlatformRoles.SUPER_ADMIN,
          'a800ea5c-667a-424a-aa09-49f6a4a8a222',
          PlatformRoles.ADMIN
        )
      ).rejects.toThrow(ConfigurationError);
    });
  });

  describe('bootstrapSuperadmin', () => {
    it('executes atomic bootstrap RPC successfully', async () => {
      const mockClient = createMockSupabaseClient({
        rpc: async () => ({ data: { status: 'SUCCESS' }, error: null }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.bootstrapSuperadmin('superadmin-uuid-001')
      ).resolves.toBeUndefined();
    });

    it('throws AuthorizationError when bootstrap is already locked', async () => {
      const mockClient = createMockSupabaseClient({
        rpc: async () => ({
          data: null,
          error: { message: 'Bootstrap locked: An initial Super Administrator already exists.' },
        }),
      });

      const userService = new SupabaseUserService({
        supabaseUrl,
        serviceRoleKey,
        supabaseClient: mockClient,
      });

      await expect(
        userService.bootstrapSuperadmin('superadmin-uuid-001')
      ).rejects.toThrow(AuthorizationError);
    });
  });
});
