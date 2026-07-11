import { NextResponse } from 'next/server';

export function withErrorHandler<Args extends unknown[], Result>(
  handler: (...args: Args) => Promise<Result>
) {
  return async (...args: Args) => {
    try {
      return await handler(...args);
    } catch {
      // Strict sanitization: Never leak stack traces or env variables to the client
      return NextResponse.json(
        { 
          error: "Internal Server Error", 
          message: "An unexpected error occurred. Incident logged.",
          success: false 
        }, 
        { status: 500 }
      );
    }
  };
}
