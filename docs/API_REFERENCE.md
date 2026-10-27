# Modular Auth Foundation: API Reference

This document provides a technical specification for all endpoints implemented in the **Modular Auth Foundation** Express API service (`@modular-auth/api`).

---

## 1. Global Conventions

### Base URL
- Local: `http://localhost:4000`
- Production (Render): `https://modular-auth-foundation.onrender.com`

### Authentication Header
Protected endpoints require a valid Supabase JWT access token sent in the `Authorization` header:
```http
Authorization: Bearer <SUPABASE_ACCESS_TOKEN>
```

### Content Type
All requests containing a JSON payload must send:
```http
Content-Type: application/json
```

### Standard Error Response Format
All errors follow a unified, sanitized structure without leaking internal database errors, secrets, or server stack traces:
```json
{
  "error": {
    "code": "UNAUTHENTICATED | FORBIDDEN | BAD_REQUEST | NOT_FOUND | RATE_LIMITED | MFA_REQUIRED | INTERNAL_ERROR",
    "message": "Human-readable description of the error",
    "details": {}
  }
}
```

---

## 2. Public Endpoints

### 2.1 Service Health Probe
Zero-downtime health check probe for load balancers and container orchestrators (e.g., Render, Kubernetes).

- **Route**: `GET /health`
- **Authentication**: None (Public)
- **Rate Limit**: Unthrottled

#### Response (`200 OK`)
```json
{
  "status": "ok",
  "timestamp": "2026-10-27T05:28:53.216Z"
}
```

---

## 3. Authenticated Identity Endpoints

### 3.1 Get Current User Profile
Retrieves the authenticated caller's profile resolved authoritatively from `public.users` in the database.

- **Route**: `GET /api/v1/auth/me`
- **Authentication**: Bearer Token required
- **Authorization**: Any authenticated user

#### Request Headers
```http
Authorization: Bearer <ACCESS_TOKEN>
```

#### Success Response (`200 OK`)
```json
{
  "user": {
    "id": "d6d1bbef-e141-4138-ac74-987070d05527",
    "email": "superadmin.modularauth@gmail.com",
    "platformRole": "superadmin"
  }
}
```

#### Error Responses
- `401 Unauthorized` (`UNAUTHENTICATED`): Missing, malformed, expired, or invalid Bearer token.
- `404 Not Found` (`USER_NOT_FOUND`): The user ID exists in Supabase Auth but has no profile row in `public.users`.

---

## 4. Platform Administration Endpoints

Platform operations require authoritative platform-level roles stored in `public.users.platform_role`. Organization roles **never** grant access to these endpoints.

### 4.1 Get Platform Metrics
Returns high-level system metrics for internal platform operators.

- **Route**: `GET /api/v1/platform/metrics`
- **Authentication**: Bearer Token required
- **Authorization**: `superadmin`, `founder`, `admin`, `developer`, `client_servicing`, `accounts`

#### Success Response (`200 OK`)
```json
{
  "metrics": {
    "activeUsers": 1250,
    "totalOrganizations": 48,
    "systemStatus": "healthy"
  }
}
```

#### Error Responses
- `403 Forbidden` (`FORBIDDEN`): Caller lacks an authorized platform role.

---

### 4.2 Get System Settings
Retrieves sensitive platform configuration parameters.

- **Route**: `GET /api/v1/platform/system-settings`
- **Authentication**: Bearer Token required
- **Authorization**: `superadmin`, `founder`

#### Success Response (`200 OK`)
```json
{
  "settings": {
    "maintenanceMode": false,
    "registrationOpen": true,
    "mfaEnforced": true
  }
}
```

#### Error Responses
- `403 Forbidden` (`FORBIDDEN`): Role is not `superadmin` or `founder` (e.g., ordinary `admin` is denied).

---

### 4.3 Execute Sensitive Platform Operation (MFA Protected)
Executes high-risk platform operations requiring elevated Multi-Factor Authentication assurance (`aal2`).

- **Route**: `POST /api/v1/platform/sensitive-operation`
- **Authentication**: Bearer Token required
- **Authorization**: `superadmin`, `founder`
- **MFA Assurance**: Requires `aal2` (TOTP challenge verification)

#### Request Headers
```http
Authorization: Bearer <AAL2_ACCESS_TOKEN>
Content-Type: application/json
```

#### Request Body
```json
{
  "action": "export_system_keys",
  "reason": "Quarterly regulatory compliance audit"
}
```

#### Success Response (`200 OK`)
```json
{
  "message": "Sensitive operation completed successfully",
  "actorId": "d6d1bbef-e141-4138-ac74-987070d05527",
  "mfaLevel": "aal2"
}
```

#### Error Responses
- `403 Forbidden` (`MFA_REQUIRED`): Token has only `aal1` assurance; step-up verification required.
```json
{
  "error": {
    "code": "MFA_REQUIRED",
    "message": "MFA assurance level 'aal2' required for this operation. Current level: 'aal1'"
  }
}
```

---

### 4.4 Update Platform User Role
Assigns or modifies a user's platform-level administrative role. Includes anti-lockout and anti-escalation safety invariants.

- **Route**: `PATCH /api/v1/platform/users/:targetUserId/role`
- **Authentication**: Bearer Token required
- **Authorization**: `superadmin`, `founder`
- **Audit Emission**: Automatically records `PLATFORM_ROLE_ASSIGNED` event in `public.audit_logs`.

#### Path Parameters
- `targetUserId` (UUID, RFC 4122): The Supabase user UUID of the user whose role is being changed.

#### Request Body
```json
{
  "role": "admin"
}
```
*Permitted roles*: `superadmin`, `founder`, `developer`, `client_servicing`, `accounts`, `admin`, `user` (or `null`).

#### Invariants Enforced
1. **Self-Escalation / Demotion Prevention**: A user cannot modify their own platform role (`req.user.id !== targetUserId`).
2. **Sole Superadmin Protection**: The final existing superadmin cannot be demoted or removed.
3. **Format Validation**: Target user ID must be a valid RFC 4122 UUID. Role name must match known platform roles.

#### Success Response (`200 OK`)
```json
{
  "message": "Platform role updated successfully for user a800ea5c-667a-424a-aa09-49f6a4a8a222",
  "targetUserId": "a800ea5c-667a-424a-aa09-49f6a4a8a222",
  "newRole": "admin"
}
```

#### Error Responses
- `400 Bad Request` (`BAD_REQUEST`): Invalid UUID format or invalid role name.
- `403 Forbidden` (`FORBIDDEN`): Caller is not `superadmin` or `founder`, or attempted self-demotion.
- `404 Not Found` (`USER_NOT_FOUND`): Target user does not exist in `public.users`.
- `409 Conflict` (`CONFLICT`): Attempted to demote or remove the last remaining Superadmin.

---

## 5. Tenant & Workspace Scoped Endpoints

Multi-tenant routes enforce tenant boundary checks. Callers must possess an active membership in the requested organization or workspace.

### Context Resolution Mechanism
The tenant or workspace identifier is extracted flexibly from:
1. URL Route Parameter: `:orgId`, `:workspaceId`, `:tenantId`
2. HTTP Request Headers:
   - `X-Organization-Id: <UUID>`
   - `X-Workspace-Id: <UUID>`
   - `X-Tenant-Id: <UUID>`
3. Query Parameters: `?orgId=<UUID>`, `?workspaceId=<UUID>`, `?tenantId=<UUID>`

Once verified, the request object is hydrated with `req.tenant`:
```typescript
req.tenant = {
  organizationId: 'c2b4d6e8-...',
  workspaceId: 'w1a2b3c4-...', // If supplied
  membership: {
    userId: 'd6d1bbef-...',
    organizationId: 'c2b4d6e8-...',
    role: 'business_owner',
    status: 'active'
  }
};
```

---

### 5.1 List Organization Projects
Lists projects belonging strictly to the requested organization or workspace.

- **Route**: `GET /api/v1/organizations/:orgId/projects`
- **Authentication**: Bearer Token required
- **Authorization**: Active member of `:orgId` (roles: `business_owner`, `leader`, `manager`, `executive`, `intern`, `collaborator`, `guest`)

#### Success Response (`200 OK`)
```json
{
  "organizationId": "c2b4d6e8-0000-0000-0000-000000000001",
  "projects": [
    {
      "id": "p100-0000-0000-0000-000000000001",
      "name": "ArchScale Platform Redesign",
      "status": "active"
    }
  ]
}
```

#### Error Responses
- `403 Forbidden` (`MEMBERSHIP_REQUIRED`): Caller is not an active member of the specified organization or membership is suspended/inactive.
- `400 Bad Request` (`BAD_REQUEST`): Missing or invalid organization UUID.

---

### 5.2 List Organization Members
Lists members belonging to the specified organization.

- **Route**: `GET /api/v1/organizations/:orgId/members`
- **Authentication**: Bearer Token required
- **Authorization**: Active member of `:orgId`

#### Success Response (`200 OK`)
```json
{
  "organizationId": "c2b4d6e8-0000-0000-0000-000000000001",
  "members": [
    {
      "userId": "d6d1bbef-e141-4138-ac74-987070d05527",
      "role": "business_owner",
      "status": "active"
    }
  ]
}
```

---

## 6. Audit Event Structure

When privileged or sensitive events occur, structured audit records are emitted to `public.audit_logs`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `UUID` | Unique audit event identifier |
| `event_type` | `VARCHAR` | Event classification (e.g., `PLATFORM_ROLE_ASSIGNED`, `MFA_STEP_UP_VERIFIED`) |
| `actor_id` | `UUID` | Supabase User UUID of the actor performing the action |
| `action` | `VARCHAR` | The specific operational action performed |
| `resource_type` | `VARCHAR` | Target resource category (`user`, `organization`, `project`) |
| `resource_id` | `VARCHAR` | Target resource UUID or identifier |
| `organization_id` | `UUID` | Target tenant identifier (nullable for platform-level events) |
| `outcome` | `VARCHAR` | `SUCCESS`, `FAILURE`, `DENIED`, `ERROR` |
| `request_id` | `VARCHAR` | Correlating HTTP request trace identifier |
| `metadata` | `JSONB` | Non-sensitive context data (**strictly sanitized**; tokens, passwords, secrets are redacted) |
| `created_at` | `TIMESTAMPTZ`| Immutable event creation timestamp |
