/**
 * Standardized API Error Handling Wrapper
 *
 * Implements D-02 from the architectural audit - prevents information leakage
 * by sanitizing error messages and providing consistent error responses.
 *
 * @author Erick | Founding Principal AI Architect
 */

import { NextRequest, NextResponse } from 'next/server';
import { ZodSchema, ZodError } from 'zod';

/**
 * Standardized API error response structure
 */
export interface ApiErrorResponse {
  error: string;
  code: string;
  details?: Record<string, string[]>;
  timestamp: string;
}

/**
 * Standardized API success response structure
 */
export interface ApiSuccessResponse<T> {
  data: T;
  timestamp: string;
}

/**
 * Error codes for consistent error classification
 */
export enum ApiErrorCode {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  NOT_FOUND = 'NOT_FOUND',
  CONFLICT = 'CONFLICT',
  RATE_LIMITED = 'RATE_LIMITED',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  BAD_REQUEST = 'BAD_REQUEST',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
}

/**
 * Custom API error class for controlled error throwing
 */
export class ApiError extends Error {
  constructor(
    public statusCode: number,
    public code: ApiErrorCode,
    message: string,
    public details?: Record<string, string[]>
  ) {
    super(message);
    this.name = 'ApiError';
  }

  static badRequest(message: string, details?: Record<string, string[]>): ApiError {
    return new ApiError(400, ApiErrorCode.BAD_REQUEST, message, details);
  }

  static unauthorized(message = 'Authentication required'): ApiError {
    return new ApiError(401, ApiErrorCode.UNAUTHORIZED, message);
  }

  static forbidden(message = 'Access denied'): ApiError {
    return new ApiError(403, ApiErrorCode.FORBIDDEN, message);
  }

  static notFound(message = 'Resource not found'): ApiError {
    return new ApiError(404, ApiErrorCode.NOT_FOUND, message);
  }

  static conflict(message: string): ApiError {
    return new ApiError(409, ApiErrorCode.CONFLICT, message);
  }

  static rateLimited(message = 'Too many requests'): ApiError {
    return new ApiError(429, ApiErrorCode.RATE_LIMITED, message);
  }

  static internal(message = 'An unexpected error occurred'): ApiError {
    return new ApiError(500, ApiErrorCode.INTERNAL_ERROR, message);
  }
}

/**
 * Create a standardized error response
 */
function createErrorResponse(
  statusCode: number,
  code: ApiErrorCode,
  message: string,
  details?: Record<string, string[]>
): NextResponse<ApiErrorResponse> {
  return NextResponse.json(
    {
      error: message,
      code,
      details,
      timestamp: new Date().toISOString(),
    },
    { status: statusCode }
  );
}

/**
 * Create a standardized success response
 */
export function createSuccessResponse<T>(data: T, status = 200): NextResponse<ApiSuccessResponse<T>> {
  return NextResponse.json(
    {
      data,
      timestamp: new Date().toISOString(),
    },
    { status }
  );
}

/**
 * Format Zod validation errors into a user-friendly structure
 */
function formatZodErrors(error: ZodError): Record<string, string[]> {
  const details: Record<string, string[]> = {};

  for (const issue of error.issues) {
    const path = issue.path.join('.') || 'root';
    if (!details[path]) {
      details[path] = [];
    }
    details[path].push(issue.message);
  }

  return details;
}

/**
 * Parse and validate request body with Zod schema
 */
export async function parseRequestBody<T>(
  request: NextRequest,
  schema: ZodSchema<T>
): Promise<T> {
  let body: unknown;

  try {
    body = await request.json();
  } catch {
    throw ApiError.badRequest('Invalid JSON in request body');
  }

  const result = schema.safeParse(body);

  if (!result.success) {
    throw new ApiError(
      400,
      ApiErrorCode.VALIDATION_ERROR,
      'Validation failed',
      formatZodErrors(result.error)
    );
  }

  return result.data;
}

/**
 * Parse and validate query parameters with Zod schema
 */
export function parseQueryParams<T>(
  request: NextRequest,
  schema: ZodSchema<T>
): T {
  const { searchParams } = new URL(request.url);
  const params: Record<string, string> = {};

  searchParams.forEach((value, key) => {
    params[key] = value;
  });

  const result = schema.safeParse(params);

  if (!result.success) {
    throw new ApiError(
      400,
      ApiErrorCode.VALIDATION_ERROR,
      'Invalid query parameters',
      formatZodErrors(result.error)
    );
  }

  return result.data;
}

/**
 * API route handler type
 */
type ApiHandlerContext = {
  params: Record<string, string>;
};

type RawRouteContext = {
  params: Promise<unknown>;
};

type ApiHandler<T = unknown> = (
  request: NextRequest,
  context?: ApiHandlerContext
) => Promise<NextResponse<T> | T>;

async function normalizeContext(context?: RawRouteContext): Promise<ApiHandlerContext> {
  if (!context) {
    return { params: {} };
  }

  const rawParams = await context.params;
  if (!rawParams || typeof rawParams !== 'object') {
    return { params: {} };
  }

  const params: Record<string, string> = {};
  for (const [key, value] of Object.entries(rawParams as Record<string, unknown>)) {
    params[key] = typeof value === 'string' ? value : String(value);
  }

  return { params };
}

/**
 * Higher-order function that wraps API route handlers with standardized
 * error handling and logging.
 *
 * Usage:
 * ```typescript
 * export const POST = apiWrapper(async (request) => {
 *   const body = await parseRequestBody(request, MySchema);
 *   // ... handler logic
 *   return { success: true };
 * });
 * ```
 */
export function apiWrapper<T>(
  handler: ApiHandler<T>
): (request: NextRequest, context: RawRouteContext) => Promise<NextResponse> {
  return async (request: NextRequest, context: RawRouteContext) => {
    const startTime = Date.now();
    const requestId = crypto.randomUUID();

    try {
      const normalizedContext = await normalizeContext(context);
      const result = await handler(request, normalizedContext);

      // If handler returns NextResponse, pass it through
      if (result instanceof NextResponse) {
        return result;
      }

      // Otherwise, wrap in success response
      return createSuccessResponse(result);
    } catch (error) {
      // Log the error internally (with full details)
      const duration = Date.now() - startTime;
      console.error(`[${requestId}] API Error after ${duration}ms:`, {
        method: request.method,
        url: request.url,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      // Handle known API errors
      if (error instanceof ApiError) {
        return createErrorResponse(
          error.statusCode,
          error.code,
          error.message,
          error.details
        );
      }

      // Handle Zod validation errors (if thrown directly)
      if (error instanceof ZodError) {
        return createErrorResponse(
          400,
          ApiErrorCode.VALIDATION_ERROR,
          'Validation failed',
          formatZodErrors(error)
        );
      }

      // Sanitize all other errors - NEVER expose internal details
      // This prevents information leakage to attackers
      return createErrorResponse(
        500,
        ApiErrorCode.INTERNAL_ERROR,
        'An unexpected error occurred. Please try again later.'
      );
    }
  };
}

/**
 * Utility to check if request is authenticated
 * Use this in API routes that require authentication
 */
export async function requireAuth(request: NextRequest): Promise<void> {
  // Import dynamically to avoid circular dependencies
  const { getAuthHeaders } = await import('./api-auth');
  const headers = await getAuthHeaders();

  if (!headers) {
    throw ApiError.unauthorized();
  }
}

/**
 * Utility to check if user has required role
 */
export async function requireRole(
  request: NextRequest,
  allowedRoles: string[]
): Promise<void> {
  // First check authentication
  await requireAuth(request);

  // Get session to check role
  const { getServerSession } = await import('next-auth');
  const { authOptions } = await import('@/lib/auth');
  const session = await getServerSession(authOptions);

  if (!session?.user?.role || !allowedRoles.includes(session.user.role)) {
    throw ApiError.forbidden('Insufficient permissions');
  }
}
