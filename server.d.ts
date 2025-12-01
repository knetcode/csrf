import type { NextRequest, NextResponse } from "next/server";

export declare class CsrfError extends Error {}

export type CsrfCookieOptions = {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  path?: string;
  maxAge?: number;
};

export type CsrfProtectOptions = {
  secret: string;
  allowedOrigins?: string | string[];
  cookie?: CsrfCookieOptions;
  cookieName?: string;
  headerName?: string;
  pageMethods?: string[];
  apiMethods?: string[];
  ttlSeconds?: number;
  allowedSkewSeconds?: number;
  tokenRotationGracePeriod?: number;
  debug?: boolean;
};

export function generateCSRFToken(length?: number): string;
export function validateCSRFToken(requestToken: string | null, cookieToken: string | null): boolean;
export function getCsrfTokenFromCookie(request: NextRequest, cookieName?: string): string | null;
export function getCsrfTokenFromHeader(request: NextRequest, headerName?: string): string | null;
export function setCsrfTokenCookie(options: {
  response: NextResponse;
  token: string;
  cookieName?: string;
  cookieOptions?: CsrfCookieOptions;
}): void;
export function rotateAndSetCsrfToken(options: {
  response: { cookies: NextResponse["cookies"]; headers: NextResponse["headers"] };
  secret: string;
  oldToken?: string | null;
  cookieName?: string;
  headerName?: string;
  cookieOptions?: CsrfCookieOptions;
  gracePeriod?: number;
}): Promise<string>;
export function getOrCreateCsrfToken(request: NextRequest, cookieName?: string): string;
export function createCsrfProtect(
  options: CsrfProtectOptions
): (request: NextRequest, response: NextResponse) => Promise<string>;
export function getCsrfTokenFromServer(cookieName?: string, headerName?: string): Promise<string>;
export function handleCsrfProtection(
  csrfProtectFn: (request: NextRequest, response: NextResponse) => Promise<string>,
  request: NextRequest,
  cookieName?: string
): Promise<{ token: string; cookieValue: string | null }>;
export function handleCsrfInMiddleware(
  options: (
    | {
        csrfProtect: (request: NextRequest, response: NextResponse) => Promise<string>;
        request: NextRequest;
        response: NextResponse;
        cookieName?: string;
        headerName?: string;
        cookieOptions?: CsrfCookieOptions;
        onError?: (error: CsrfError) => NextResponse;
      }
    | (CsrfProtectOptions & {
        request: NextRequest;
        response: NextResponse;
        cookieName?: string;
        headerName?: string;
        cookieOptions?: CsrfCookieOptions;
        onError?: (error: CsrfError) => NextResponse;
      })
  )
): Promise<NextResponse>;
// Client helper available from subpath export only: @lib/csrf/client
