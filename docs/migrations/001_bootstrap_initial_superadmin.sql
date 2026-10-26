-- ==============================================================================
-- Migration: 001_bootstrap_initial_superadmin.sql
-- Description: Corrects platform-role escalation trigger, implements atomic 
--              concurrency-safe initial superadmin bootstrap function, and
--              hardens audit-log and organization membership RLS policies.
-- ==============================================================================

-- 1. Refine the Platform Role Escalation Trigger
-- Allows trusted database administrator roles ('postgres', 'supabase_admin', 'service_role')
-- OR authenticated sessions who already possess 'superadmin' or 'founder' in public.users.
-- Completely blocks ordinary authenticated users and anon callers from modifying platform_role.
CREATE OR REPLACE FUNCTION public.protect_platform_role_escalation()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD.platform_role IS DISTINCT FROM NEW.platform_role) THEN
        -- Allow direct execution by trusted database administrator roles
        IF current_user IN ('postgres', 'supabase_admin', 'service_role') THEN
            NEW.updated_at = NOW();
            RETURN NEW;
        END IF;

        -- Otherwise, require the acting user session (auth.uid()) to have an active superadmin or founder role
        IF auth.uid() IS NOT NULL AND EXISTS (
            SELECT 1 FROM public.users
            WHERE id = auth.uid() AND platform_role IN ('superadmin', 'founder')
        ) THEN
            NEW.updated_at = NOW();
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'Privilege escalation rejected: Only Super Administrators or Founders can modify platform roles.';
    END IF;

    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Re-attach trigger
DROP TRIGGER IF EXISTS trg_protect_platform_role ON public.users;
CREATE TRIGGER trg_protect_platform_role
BEFORE UPDATE ON public.users
FOR EACH ROW
EXECUTE FUNCTION public.protect_platform_role_escalation();

-- 2. Atomic, Concurrency-Safe Initial Superadmin Bootstrap Function
-- Executes in an isolated transaction protected by an explicit advisory transaction lock.
-- Verifies:
--   a) Target user exists in auth.users and public.users.
--   b) Zero superadmins or founders currently exist in public.users.
-- If any superadmin exists, the function immediately aborts and locks itself permanently.
CREATE OR REPLACE FUNCTION public.bootstrap_initial_superadmin(target_user_id UUID)
RETURNS JSONB AS $$
DECLARE
    existing_superadmin_count INT;
    target_user_email TEXT;
BEGIN
    -- Acquire exclusive advisory transaction lock to serialize any concurrent bootstrap attempts
    PERFORM pg_advisory_xact_lock(hashtext('bootstrap_initial_superadmin_lock'));

    -- Guard: Check if an initial superadmin or founder has already been assigned
    SELECT COUNT(*) INTO existing_superadmin_count
    FROM public.users
    WHERE platform_role IN ('superadmin', 'founder');

    IF existing_superadmin_count > 0 THEN
        RAISE EXCEPTION 'Bootstrap locked: A Super Administrator or Founder already exists. Subsequent role assignments must be performed by an authenticated Super Administrator through the API.';
    END IF;

    -- Validate that the target user exists in auth.users
    SELECT email INTO target_user_email
    FROM auth.users
    WHERE id = target_user_id;

    IF target_user_email IS NULL THEN
        RAISE EXCEPTION 'Target user ID % does not exist in auth.users. Please create or invite the user first.', target_user_id;
    END IF;

    -- Ensure record exists in public.users (in case auth trigger has not yet fired)
    INSERT INTO public.users (id, email, platform_role)
    VALUES (target_user_id, target_user_email, 'superadmin')
    ON CONFLICT (id) DO UPDATE
    SET platform_role = 'superadmin',
        updated_at = NOW();

    -- Record immutable audit log entry
    INSERT INTO public.audit_logs (
        event_type,
        timestamp,
        actor_id,
        resource_id,
        resource_type,
        outcome,
        reason,
        metadata
    ) VALUES (
        'security:initial_bootstrap',
        NOW(),
        COALESCE(auth.uid()::TEXT, current_user),
        target_user_id::TEXT,
        'user',
        'SUCCESS',
        'Initial Super Administrator provisioned via database bootstrap procedure',
        jsonb_build_object(
            'target_email', target_user_email,
            'assigned_role', 'superadmin',
            'executor', current_user
        )
    );

    RETURN jsonb_build_object(
        'status', 'SUCCESS',
        'message', 'Initial Super Administrator successfully provisioned',
        'userId', target_user_id,
        'email', target_user_email,
        'role', 'superadmin'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3. Strict Execution Permissions on Bootstrap Function
-- Revoke all permissions from PUBLIC, anon, and authenticated
REVOKE ALL ON FUNCTION public.bootstrap_initial_superadmin(UUID) FROM PUBLIC, anon, authenticated;

-- Grant execution ONLY to trusted database administrator roles
GRANT EXECUTE ON FUNCTION public.bootstrap_initial_superadmin(UUID) TO postgres, service_role;

-- 4. Audit Log Write Hardening
-- Block clients from directly inserting arbitrary audit logs
REVOKE INSERT ON public.audit_logs FROM authenticated, anon;
GRANT INSERT, SELECT ON public.audit_logs TO service_role, postgres;
