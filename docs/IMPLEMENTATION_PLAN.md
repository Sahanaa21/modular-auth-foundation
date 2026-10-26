# Modular Auth Foundation: Phased Implementation Plan

This document outlines the phased delivery roadmap for the Modular Auth Foundation. Implementation proceeds in distinct milestones to guarantee testability, maintainability, and architectural integrity at each step.

---

## Milestone Breakdown

### Milestone 1: Monorepo Foundation & Core Package (`packages/auth-core`)
**Objective**: Establish the workspace structure, package tooling, core TypeScript types, authorization engine, permission matrices, and unit tests.
- **Deliverables**:
  - Root `package.json` with npm workspaces (`packages/*`, `apps/*`).
  - Base TypeScript, ESLint, Prettier, and Vitest configuration.
  - Core interfaces (`roles.ts`, `permissions.ts`, `auth.ts`, `context.ts`, `audit.ts`).
  - Configurable `PermissionMatrix` implementation.
  - `AuthorizationEngine` implementation (evaluating platform vs org roles, fail-closed policy).
  - Error classes (`AuthenticationError`, `AuthorizationError`, `TenantError`).
  - Vitest test suite for role evaluation, permission checks, and edge cases.
- **Verification Gate**:
  - Run `npm test` across `packages/auth-core`. 100% passing tests for authorization matrix logic.

---

### Milestone 2: Backend API Architecture & Security Middleware (`apps/api`)
**Objective**: Build the Express.js service with strict environment validation, security headers, rate limiting, and core middleware.
- **Deliverables**:
  - Zod-based environment variable configuration (`src/config/env.ts`) with `.env.example`.
  - Supabase client integration & mockable `ITokenVerifier` (supporting JWKS / JWT verification).
  - Express middleware suite:
    - `securityHeaders` (Helmet)
    - `cors` configuration
    - `rateLimiter` (Express-rate-limit)
    - `authenticate` (Bearer token extraction and validation)
    - `requireOrgMembership` (Tenant isolation and membership verification)
    - `requirePermission` (RBAC/PBAC enforcement)
    - `validateRequest` (Zod request schema validator)
    - `errorHandler` (Centralized sanitized error handler)
  - Security audit logger implementation (`IAuditLogger`).
- **Verification Gate**:
  - Supertest automated tests for:
    - Missing credentials (401)
    - Invalid / expired token (401)
    - Valid token authentication (200)
    - Rate limiter activation (429)
    - Input validation failure (400)

---

### Milestone 3: Authorization Data Store & Tenant Isolation Services
**Objective**: Implement database schema, organization service, and resource-level access control.
- **Deliverables**:
  - Database schema migration script (`docs/DATABASE_SCHEMA.sql`) defining:
    - `users` (linked to `auth.users`)
    - `organizations`
    - `organization_memberships`
    - `audit_logs`
    - RLS policies and indexes.
  - `OrganizationService` implementation (fetching memberships, validating tenant access).
  - Organization and tenant management endpoints:
    - `GET /api/v1/organizations` (list user's organizations)
    - `GET /api/v1/organizations/:orgId` (get organization details)
    - `POST /api/v1/organizations/:orgId/members` (invite member)
    - `PATCH /api/v1/organizations/:orgId/members/:memberId` (update member role)
  - Sample protected tenant resource endpoints (e.g., `/api/v1/organizations/:orgId/projects`).
- **Verification Gate**:
  - Automated tests verifying:
    - Cross-tenant access rejection (Organization A member attempting to access Organization B resource)
    - Platform role actions vs Organization role actions
    - Insecure Direct Object Reference (IDOR) prevention
    - Audit log entry creation upon access denial.

---

### Milestone 4: Frontend Demonstration Application (`apps/web`)
**Objective**: Build a clean, responsive demonstration application in React, Vite, and TypeScript illustrating the end-to-end authentication and authorization workflow.
- **Deliverables**:
  - Vite + React + TypeScript setup with modern, accessible styling.
  - Supabase Auth client integration (Login, Registration, Password Reset, Logout).
  - React Auth Context & custom hooks (`useAuth`, `useTenant`, `usePermission`).
  - Protected route wrappers (`ProtectedRoute`, `RequireRole`, `RequirePermission`).
  - Demonstration dashboards:
    - **Platform Dashboard**: Visible only to users with Platform Roles (`founder`, `developer`, etc.).
    - **Organization Workspace**: Allows switching active organizations and displaying tenant-scoped resources.
    - **Role & Permission Inspector**: Visualizes user's current token, claims, role, and evaluated permissions.
  - Frontend environment validation (`.env.example`).
- **Verification Gate**:
  - End-to-end integration test of login -> token acquisition -> API request -> role-based UI rendering.

---

### Milestone 5: Automated Test Suite & CI/CD Pipeline
**Objective**: Consolidate automated tests, coverage reporting, and GitHub Actions continuous integration.
- **Deliverables**:
  - Unit tests for all pure logic in `packages/auth-core`.
  - Integration tests for Express API endpoints using Supertest and Supabase test mocks.
  - End-to-end test scenarios.
  - GitHub Actions workflow (`.github/workflows/ci.yml`) running lint, typecheck, and tests.
- **Verification Gate**:
  - Full CI run succeeds locally and in pipeline without flaky tests or network dependencies.

---

### Milestone 6: Practical Integration Documentation & Migration Guide
**Objective**: Document how third-party applications can consume this foundation without coupling to internal implementation details.
- **Deliverables**:
  - `docs/INTEGRATION_GUIDE.md`: Step-by-step instructions for adding the foundation to a new backend or frontend.
  - `docs/SECURITY_CHECKLIST.md`: Production deployment checklist (RLS verification, key rotation, rate limits, secrets management).
  - Example consumption snippets.
- **Verification Gate**:
  - Comprehensive documentation review against user requirements.
