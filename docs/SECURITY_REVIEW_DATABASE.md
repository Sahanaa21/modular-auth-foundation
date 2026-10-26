# Database Security & RLS Policy Review

**Date**: October 2026  
**Auditor**: Application Security Architect  
**Subject**: Supabase PostgreSQL Schema, RLS Policies, and Role Protection Model

---

## Executive Summary

This review assesses the database authorization controls defined in [`docs/DATABASE_SCHEMA.sql`](file:///c:/Users/sahan/OneDrive/Desktop/ArchScale/modular-auth-foundation/docs/DATABASE_SCHEMA.sql) and [`docs/migrations/001_bootstrap_initial_superadmin.sql`](file:///c:/Users/sahan/OneDrive/Desktop/ArchScale/modular-auth-foundation/docs/migrations/001_bootstrap_initial_superadmin.sql). It analyzes Row Level Security (RLS), trigger enforcement, privilege escalation vectors, and multi-tenant isolation.

---

## 1. Findings & Mitigations

### Finding 1: Initial Bootstrap Chicken-and-Egg Deadlock (Resolved)
- **Severity**: High (Availability / Administrative Provisioning)
- **Vulnerability**: The initial `protect_platform_role_escalation` trigger rejected all `platform_role` mutations unless the acting session was already an existing `superadmin` or `founder`. When initializing a new project where zero superadmins exist, the database entered an unresolvable state blocking initial setup.
- **Root Cause**: In the Supabase SQL Editor, queries execute under database role `postgres` where `auth.uid()` is `NULL`. The previous condition `current_user <> 'service_role'` failed to recognize `postgres` and `supabase_admin`.
- **Mitigation**: Implemented `public.bootstrap_initial_superadmin(target_user_id UUID)` with `pg_advisory_xact_lock` and updated the trigger to permit trusted database roles (`postgres`, `supabase_admin`, `service_role`).

---

### Finding 2: Concurrency & Race Conditions in Initial Superadmin Bootstrap (Resolved)
- **Severity**: High (Privilege Integrity)
- **Vulnerability**: If multiple administrative provisioning requests run concurrently during project initialization, both could read `COUNT(superadmin) == 0` before either commits, creating multiple superadmins inadvertently.
- **Mitigation**: An explicit transaction-level advisory lock is acquired at the start of `public.bootstrap_initial_superadmin`:
  ```sql
  PERFORM pg_advisory_xact_lock(hashtext('bootstrap_initial_superadmin_lock'));
  ```
  This serializes all concurrent bootstrap attempts within their respective transactions. The first transaction commits the superadmin; all subsequent concurrent transactions see `COUNT > 0` and fail closed.

---

### Finding 3: Audit Log Client Write Poisoning (Resolved)
- **Severity**: Medium (Audit Integrity)
- **Vulnerability**: If client roles (`authenticated`, `anon`) have `INSERT` permissions on `public.audit_logs`, a compromised client token could forge audit events, tamper with event logs, or flood the storage.
- **Mitigation**:
  1. Revoked `INSERT` from client roles:
     ```sql
     REVOKE INSERT ON public.audit_logs FROM authenticated, anon;
     ```
  2. Granted write access exclusively to backend system roles:
     ```sql
     GRANT INSERT, SELECT ON public.audit_logs TO service_role, postgres;
     ```
  3. Client applications must emit audit events via the backend API's `IAuditLogger`.

---

### Finding 4: Organization Membership RLS Policy Scope & Role Usurpation (Addressed)
- **Severity**: Medium (Tenant Privilege Escalation)
- **Vulnerability**: The policy `memberships_manage_owners_leaders` used `FOR ALL` with a `USING` clause checking if the actor is a `business_owner` or `leader`.
  - Without an explicit `WITH CHECK` clause on `UPDATE`, a `leader` could potentially elevate another member or themselves to `business_owner`.
  - A `leader` could theoretically delete the `business_owner`'s membership.
- **Mitigation**:
  1. Split membership management policies:
     - `business_owner` can manage all roles in their organization.
     - `leader` can only invite, update, or remove subordinate roles (`manager`, `executive`, `intern`, `collaborator`, `guest`), and **cannot** modify `business_owner` records or promote anyone to `business_owner`.
  2. Added explicit `WITH CHECK` constraints to prevent updating tenant membership across organization boundaries.

---

### Finding 5: Direct Column-Level Escalation on `public.users` (Resolved)
- **Severity**: Critical (Privilege Escalation)
- **Vulnerability**: If an authenticated client executed `UPDATE public.users SET platform_role = 'superadmin'`, relying solely on application-level filtering would be insecure.
- **Mitigation (Defense-in-Depth)**:
  1. **Privilege Revocation**: `REVOKE UPDATE (platform_role) ON public.users FROM authenticated, anon;`
  2. **Security Trigger**: `trg_protect_platform_role` verifies that `current_user` is a trusted database role or `auth.uid()` has `platform_role IN ('superadmin', 'founder')`.
  3. **RLS Policy**: `users_update_own_profile` uses `WITH CHECK (auth.uid() = id)` and does not grant column-level permission for `platform_role`.

---

## 2. Summary of Hardened Permissions

| Table | Role `anon` | Role `authenticated` | Role `service_role` / `postgres` |
| :--- | :--- | :--- | :--- |
| `public.users` | None | `SELECT` (own profile or admin read), `UPDATE` (profile only, no roles) | Full (`ALL`) |
| `public.organizations` | None | `SELECT` (member orgs only) | Full (`ALL`) |
| `public.organization_memberships` | None | `SELECT` (same org), `INSERT/UPDATE/DELETE` (owners/leaders for subordinates) | Full (`ALL`) |
| `public.projects` | None | `SELECT/INSERT/UPDATE/DELETE` (tenant-scoped) | Full (`ALL`) |
| `public.audit_logs` | None | `SELECT` (admins only), **No INSERT** | Full (`ALL`) |
| `public.bootstrap_initial_superadmin()` | **REVOKED** | **REVOKED** | **EXECUTE GRANTED** |
