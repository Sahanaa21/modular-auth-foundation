import { z } from 'zod';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { ConfigurationError } from '@modular-auth/core';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function resolveCandidateEnvFiles(): string[] {
  const candidates: string[] = [
    // 1. Current working directory
    path.resolve(process.cwd(), '.env'),
    path.resolve(process.cwd(), 'apps/api/.env'),

    // 2. Relative to this module:
    // When executing src/config/env.ts or dist/config/env.js:
    // __dirname is <repo>/apps/api/[src|dist]/config -> 3 levels up reaches repo root
    path.resolve(__dirname, '../../../.env'),
    path.resolve(__dirname, '../../.env'),
    path.resolve(__dirname, '../.env'),
  ];

  // 3. Walk upwards to locate directory with .git or package.json
  let curr = __dirname;
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, '.git')) || fs.existsSync(path.join(curr, 'package.json'))) {
      const rootEnv = path.join(curr, '.env');
      if (!candidates.includes(rootEnv)) {
        candidates.push(rootEnv);
      }
    }
    curr = path.dirname(curr);
  }

  return Array.from(new Set(candidates));
}

const candidateEnvFiles = resolveCandidateEnvFiles();
const loadedEnvFiles: string[] = [];

for (const envPath of candidateEnvFiles) {
  if (fs.existsSync(envPath) && !loadedEnvFiles.includes(envPath)) {
    // Preserve process.env variables injected by hosting platforms (e.g., Render's PORT)
    dotenv.config({ path: envPath, override: false });
    loadedEnvFiles.push(envPath);
  }
}

if (loadedEnvFiles.length > 0) {
  console.info(`[config/env] Loaded environment configuration from: ${loadedEnvFiles.join(', ')}`);
} else {
  console.warn('[config/env] No .env file found in workspace or repository root. Using environment variables and defaults.');
}

export const envSchema = z.object({
  PORT: z.coerce.number().default(4000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  SUPABASE_URL: z
    .string()
    .url('SUPABASE_URL must be a valid URL')
    .default('https://vsllykwuqqmbitxvpuod.supabase.co'),
  SUPABASE_SERVICE_ROLE_KEY: z
    .string()
    .optional(),
  SUPABASE_JWT_SECRET: z
    .string()
    .optional(),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100),
  AUTH_RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(10),
});

export type Env = z.infer<typeof envSchema>;

/**
 * Validates the provided environment or defaults to process.env.
 * Throws a clean ConfigurationError if invalid.
 */
export function validateEnv(rawEnv: Record<string, unknown> = process.env): Env {
  const result = envSchema.safeParse(rawEnv);
  if (!result.success) {
    const errorDetails = result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', ');
    throw new ConfigurationError(`Environment configuration error: ${errorDetails}`, {
      issues: result.error.issues,
    });
  }

  const parsed = result.data;
  if (
    parsed.NODE_ENV === 'production' &&
    (!parsed.SUPABASE_SERVICE_ROLE_KEY || parsed.SUPABASE_SERVICE_ROLE_KEY.includes('placeholder'))
  ) {
    throw new ConfigurationError('SUPABASE_SERVICE_ROLE_KEY is required in production environment.');
  }

  return parsed;
}

export const env = validateEnv();
