import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { ratelimit } from '@/lib/ratelimit';
import { getClientIp } from '@/lib/client-ip';
import authConfig from "./auth.config";
import NextAuth from "next-auth";

const { auth } = NextAuth(authConfig);

export async function middleware(request: NextRequest) {
  const token = req.auth;
  
  if (request.nextUrl.pathname.startsWith('/api/og') && ratelimit) {
    const ip = getClientIp(request.headers);
    const { success } = await ratelimit.limit(ip);
    
    if (!success) {
      return new NextResponse('Too Many Requests', { status: 429 });
    }
  }
  
  // RBAC Admin Route Guarding
  if (request.nextUrl.pathname.startsWith('/admin')) {
    const roles = (token?.user?.roles as string[]) || [];
    if (!token || !roles.includes("ADMIN")) {
      return NextResponse.redirect(new URL('/', request.nextUrl));
    }
  }

  return NextResponse.next();
});

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
