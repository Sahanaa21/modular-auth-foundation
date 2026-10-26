import { z } from 'zod';
import dotenv from 'dotenv';
import { ConfigurationError } from '@modular-auth/core';

// Load environment variables from .env if present
dotenv.config();

export const envSchema = z.object({
  PORT: z.coerce.number().default(4000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  SUPABASE_URL: z.string().url('SUPABASE_URL must be a valid URL').default('https://example.supabase.co'),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1, 'SUPABASE_SERVICE_ROLE_KEY is required').default('mock-service-role-key-for-tests'),
  SUPABASE_JWT_SECRET: z.string().min(1, 'SUPABASE_JWT_SECRET is required').default('mock-jwt-secret-at-least-32-chars-long-test!'),
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
  return result.data;
}

export const env = validateEnv();
