import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';

export interface RateLimiterOptions {
  readonly windowMs: number;
  readonly max: number;
  readonly message?: string;
}

/**
 * Creates an Express rate limiter instance returning structured 429 JSON responses.
 */
export function createRateLimiter(options: RateLimiterOptions): RateLimitRequestHandler {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    standardHeaders: true, // Draft-6 RateLimit headers (RateLimit-Limit, etc.)
    legacyHeaders: false, // X-RateLimit-* disabled
    statusCode: 429,
    message: {
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: options.message ?? 'Too many requests, please try again later.',
      },
    },
    handler: (_req, res, _next, optionsUsed) => {
      res.status(optionsUsed.statusCode).json(optionsUsed.message);
    },
  });
}
