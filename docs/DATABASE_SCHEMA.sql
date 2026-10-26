-- ==============================================================================
-- Modular Auth Foundation: PostgreSQL Database Schema & Security Policies
-- Target Database: Supabase PostgreSQL (PostgreSQL 15+)
-- ==============================================================================

-- Enable UUID extension if not already present
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==============================================================================
-- 1. Tables
-- ==============================================================================

-- 1.1 Users Profile Table (Application user identity linked to auth.users)
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    platform_role TEXT CHECK (
        platform_role IS NULL OR 
        platform_role IN ('superadmin', 'admin', 'founder', 'developer', 'client_servicing', 'accounts')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for platform role lookups
CREATE INDEX IF NOT EXISTS idx_users_platform_role ON public.users(platform_role);

-- 1.2 Organizations Table (Multi-tenant workspaces)
CREATE TABLE IF NOT EXISTS public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON public.organizations(slug);

-- 1.3 Organization Memberships Table (Tenancy association & Organization roles)
CREATE TABLE IF NOT EXISTS public.organization_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (
        role IN ('business_owner', 'leader', 'manager', 'executive', 'intern', 'collaborator', 'guest')
    ),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invited', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_user_org ON public.organization_memberships(user_id, organization_id);
CREATE INDEX IF NOT EXISTS idx_memberships_org_role ON public.organization_memberships(organization_id, role);

-- 1.4 Sample Tenant Resource Table: Projects (Tenant isolation demonstration)
CREATE TABLE IF NOT EXISTS public.projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_projects_organization_id ON public.projects(organization_id);

-- 1.5 Security Audit Logs Table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id TEXT NOT NULL,
    organization_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
    resource_id TEXT,
    resource_type TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED', 'ERROR')),
    reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_timestamp ON public.audit_logs(actor_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_timestamp ON public.audit_logs(organization_id, timestamp DESC);

-- ==============================================================================
-- 2. Automation Triggers: Sync New auth.users to public.users
-- ==============================================================================

-- Function: Automatically provision public.users record on Supabase auth.users signup
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.users (id, email, platform_role)
    VALUES (NEW.id, NEW.email, NULL)
    ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email,
        updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger fired after an auth.users record is created
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.handle_new_auth_user();

-- ==============================================================================
-- 3. Security Triggers: Prevent Self-Escalation of Platform Roles
-- ==============================================================================

CREATE OR REPLACE FUNCTION public.protect_platform_role_escalation()
RETURNS TRIGGER AS $$
BEGIN
    -- Detect attempts to modify platform_role
    IF (OLD.platform_role IS DISTINCT FROM NEW.platform_role) THEN
        -- Only service_role (backend superuser) or a verified superadmin/founder can change platform_role
        IF (current_user <> 'service_role') AND NOT EXISTS (
            SELECT 1 FROM public.users
            WHERE id = auth.uid() AND platform_role IN ('superadmin', 'founder')
        ) THEN
            RAISE EXCEPTION 'Privilege escalation rejected: Only Super Administrators or Founders can modify platform roles.';
        END IF;
    END IF;

    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trg_protect_platform_role ON public.users;
CREATE TRIGGER trg_protect_platform_role
BEFORE UPDATE ON public.users
FOR EACH ROW
EXECUTE FUNCTION public.protect_platform_role_escalation();

-- ==============================================================================
-- 4. Row Level Security (RLS) Policies
-- ==============================================================================

-- Enable RLS across all tables
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- 4.1 public.users Policies
-- Users can view their own profile
CREATE POLICY "users_read_own_profile"
ON public.users
FOR SELECT
TO authenticated
USING (auth.uid() = id);

-- Superadmins and Admins can view all user profiles
CREATE POLICY "users_read_admin"
ON public.users
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.users u
        WHERE u.id = auth.uid() AND u.platform_role IN ('superadmin', 'admin', 'founder')
    )
);

-- Users can update basic profile fields (not platform_role due to column privilege & trigger)
CREATE POLICY "users_update_own_profile"
ON public.users
FOR UPDATE
TO authenticated
USING (auth.uid() = id)
WITH CHECK (auth.uid() = id);

-- Revoke direct platform_role update from client roles
REVOKE UPDATE (platform_role) ON public.users FROM authenticated, anon;

-- 4.2 public.organizations Policies
-- Members can view organizations they belong to
CREATE POLICY "org_members_read"
ON public.organizations
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.organization_memberships m
        WHERE m.organization_id = organizations.id 
          AND m.user_id = auth.uid() 
          AND m.status = 'active'
    )
);

-- Platform Superadmins can view all organizations
CREATE POLICY "org_superadmin_read_all"
ON public.organizations
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.users u
        WHERE u.id = auth.uid() AND u.platform_role IN ('superadmin', 'founder')
    )
);

-- 4.3 public.organization_memberships Policies
-- Members can view memberships within their own organization
CREATE POLICY "memberships_view_same_org"
ON public.organization_memberships
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.organization_memberships my_m
        WHERE my_m.organization_id = organization_memberships.organization_id
          AND my_m.user_id = auth.uid()
          AND my_m.status = 'active'
    )
);

-- Business owners and leaders can invite or update members in their org
CREATE POLICY "memberships_manage_owners_leaders"
ON public.organization_memberships
FOR ALL
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.organization_memberships my_m
        WHERE my_m.organization_id = organization_memberships.organization_id
          AND my_m.user_id = auth.uid()
          AND my_m.status = 'active'
          AND my_m.role IN ('business_owner', 'leader')
    )
);

-- 4.4 public.projects Policies (Tenant isolation)
-- Members can view projects belonging to their organization
CREATE POLICY "projects_read_tenant_members"
ON public.projects
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.organization_memberships m
        WHERE m.organization_id = projects.organization_id
          AND m.user_id = auth.uid()
          AND m.status = 'active'
    )
);

-- Members with create/update permissions (business_owner, leader, manager, executive, collaborator) can insert/update
CREATE POLICY "projects_mutate_tenant_members"
ON public.projects
FOR ALL
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.organization_memberships m
        WHERE m.organization_id = projects.organization_id
          AND m.user_id = auth.uid()
          AND m.status = 'active'
          AND m.role IN ('business_owner', 'leader', 'manager', 'executive', 'collaborator')
    )
);

-- 4.5 public.audit_logs Policies
-- Audit logs are insert-only via backend service_role or server API
CREATE POLICY "audit_logs_read_admins"
ON public.audit_logs
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.users u
        WHERE u.id = auth.uid() AND u.platform_role IN ('superadmin', 'admin', 'founder')
    )
);

-- ==============================================================================
-- 5. Safe Administrative Account Provisioning Example
-- ==============================================================================
-- IMPORTANT:
-- Do not run these with raw email queries without verified UUIDs.
-- Once superadmin.modularauth@gmail.com and admin.modularauth@gmail.com sign up,
-- look up their UUID from auth.users and run:
--
-- UPDATE public.users
-- SET platform_role = 'superadmin'
-- WHERE id = '<SUPERADMIN_AUTH_USER_UUID>';
--
-- UPDATE public.users
-- SET platform_role = 'admin'
-- WHERE id = '<ADMIN_AUTH_USER_UUID>';
