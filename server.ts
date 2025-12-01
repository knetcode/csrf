import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

/**
 * Custom error class for CSRF token validation failures
 */
export class CsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CsrfError";
  }
}

/**
 * Cookie options for CSRF token storage
 */
export type CsrfCookieOptions = {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  path?: string;
  maxAge?: number;
};

/**
 * Options for creating CSRF protection middleware
 */
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

/**
 * Generates a cryptographically secure random token
 * @param length - The length of the token in bytes (default: 32)
 * @returns A random token as a base64-encoded string
 */
export function generateCSRFToken(length: number = 32): string {
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return bytesToBase64(randomBytes);
}

function toBase64Url(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(b64);
}

function bytesToBase64(bytes: Uint8Array): string {
  const Buf = (globalThis as any).Buffer as any;
  if (typeof Buf !== "undefined") {
    return Buf.from(bytes).toString("base64");
  }
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // btoa is available in browsers/edge runtime
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const Buf = (globalThis as any).Buffer as any;
  if (typeof Buf !== "undefined") {
    return new Uint8Array(Buf.from(b64, "base64"));
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function hmacSha256(message: Uint8Array, secretRaw: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    secretRaw.buffer as ArrayBuffer,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, message.buffer as ArrayBuffer);
  return new Uint8Array(sig);
}

function u32ToBigEndianBytes(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (value >>> 24) & 0xff;
  buf[1] = (value >>> 16) & 0xff;
  buf[2] = (value >>> 8) & 0xff;
  buf[3] = value & 0xff;
  return buf;
}

function bigEndianBytesToU32(bytes: Uint8Array): number {
  if (bytes.length !== 4) return 0;
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
}

async function generateSignedToken(secret: string, nonceLength: number = 32): Promise<string> {
  const nonceBytes = new Uint8Array(nonceLength);
  crypto.getRandomValues(nonceBytes);
  const issuedAt = Math.floor(Date.now() / 1000);
  const tsBytes = u32ToBigEndianBytes(issuedAt);
  const toSign = new Uint8Array(nonceBytes.length + tsBytes.length);
  toSign.set(nonceBytes, 0);
  toSign.set(tsBytes, nonceBytes.length);
  const sig = await hmacSha256(toSign, base64ToBytes(secret));
  return `${toBase64Url(nonceBytes)}.${toBase64Url(tsBytes)}.${toBase64Url(sig)}`;
}

/**
 * Parse multiple tokens from a cookie value (separated by |)
 */
function parseMultipleTokens(cookieValue: string | null): string[] {
  if (!cookieValue) return [];
  return cookieValue.split("|").filter((t) => t.length > 0);
}

/**
 * Combine multiple tokens into a single cookie value
 */
function combineTokens(tokens: string[]): string {
  return tokens.join("|");
}

/**
 * Clean up expired tokens from a list, keeping only those within grace period
 */
async function cleanupExpiredTokens(
  tokens: string[],
  secret: string,
  gracePeriodSeconds: number
): Promise<string[]> {
  const now = Math.floor(Date.now() / 1000);
  const validTokens: string[] = [];
  
  for (const token of tokens) {
    const parts = token.split(".");
    if (parts.length !== 3) continue;
    
    try {
      const tsBytes = fromBase64Url(parts[1]);
      if (tsBytes.length !== 4) continue;
      const issuedAt = bigEndianBytesToU32(tsBytes);
      
      // Keep token if it's within grace period
      if (now - issuedAt <= gracePeriodSeconds) {
        validTokens.push(token);
      }
    } catch {
      // Skip invalid tokens
      continue;
    }
  }
  
  return validTokens;
}

async function verifySignedTokenWithTTL(
  token: string,
  secret: string,
  ttlSeconds: number,
  allowedSkewSeconds: number
): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 3) return false; // strict: old tokens rejected
  const [noncePart, tsPart, sigPart] = parts;
  const nonceBytes = fromBase64Url(noncePart);
  const tsBytes = fromBase64Url(tsPart);
  if (tsBytes.length !== 4) return false;
  const issuedAt = bigEndianBytesToU32(tsBytes);
  const now = Math.floor(Date.now() / 1000);
  if (issuedAt === 0) return false;
  if (now + allowedSkewSeconds < issuedAt) return false;
  if (now - issuedAt > ttlSeconds + allowedSkewSeconds) return false;
  const toSign = new Uint8Array(nonceBytes.length + tsBytes.length);
  toSign.set(nonceBytes, 0);
  toSign.set(tsBytes, nonceBytes.length);
  const expectedSig = await hmacSha256(toSign, base64ToBytes(secret));
  const providedSig = fromBase64Url(sigPart);
  if (expectedSig.byteLength !== providedSig.byteLength) return false;
  let result = 0;
  for (let i = 0; i < expectedSig.byteLength; i++) {
    result |= expectedSig[i] ^ providedSig[i];
  }
  return result === 0;
}

/**
 * Verify a token that might contain multiple tokens (for grace period support)
 * Tries each token and returns true if ANY are valid
 */
async function verifyTokenWithGracePeriod(
  cookieValue: string | null,
  headerToken: string | null,
  secret: string,
  ttlSeconds: number,
  allowedSkewSeconds: number
): Promise<boolean> {
  if (!cookieValue || !headerToken) return false;
  
  // Parse multiple tokens from cookie
  const cookieTokens = parseMultipleTokens(cookieValue);
  if (cookieTokens.length === 0) return false;
  
  // Header token must match one of the cookie tokens (constant-time)
  let headerMatchesCookie = false;
  for (const cookieToken of cookieTokens) {
    if (validateCSRFToken(headerToken, cookieToken)) {
      headerMatchesCookie = true;
      break;
    }
  }
  
  if (!headerMatchesCookie) return false;
  
  // Verify signature of the matched token
  return await verifySignedTokenWithTTL(headerToken, secret, ttlSeconds, allowedSkewSeconds);
}

async function getOrCreateSignedToken(
  request: NextRequest,
  response: NextResponse,
  cookieName: string,
  secret: string,
  cookieOptions: CsrfCookieOptions,
  ttlSeconds: number,
  allowedSkewSeconds: number
): Promise<string> {
  const existing = getCsrfTokenFromCookie(request, cookieName);
  if (
    existing &&
    (await verifySignedTokenWithTTL(existing, secret, ttlSeconds, allowedSkewSeconds))
  ) {
    return existing;
  }
  const token = await generateSignedToken(secret);
  setCsrfTokenCookie({ response, token, cookieName, cookieOptions });
  return token;
}

/**
 * Validates a CSRF token against the token stored in cookies
 * @param requestToken - The token from the request header
 * @param cookieToken - The token from the cookie
 * @returns True if tokens match, false otherwise
 */
export function validateCSRFToken(
  requestToken: string | null,
  cookieToken: string | null
): boolean {
  if (!requestToken || !cookieToken) {
    return false;
  }

  // Use constant-time comparison to prevent timing attacks
  if (requestToken.length !== cookieToken.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < requestToken.length; i++) {
    result |= requestToken.charCodeAt(i) ^ cookieToken.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Gets the CSRF token from a request's cookies
 * @param request - The incoming Next.js request
 * @param cookieName - The name of the cookie containing the CSRF token
 * @returns The CSRF token or null if not found
 */
export function getCsrfTokenFromCookie(
  request: NextRequest,
  cookieName: string = "csrf-token"
): string | null {
  const cookie = request.cookies.get(cookieName);
  return cookie?.value ?? null;
}

/**
 * Gets the CSRF token from a request's headers
 * @param request - The incoming Next.js request
 * @param headerName - The name of the header containing the CSRF token
 * @returns The CSRF token or null if not found
 */
export function getCsrfTokenFromHeader(
  request: NextRequest,
  headerName: string = "x-csrf-token"
): string | null {
  return request.headers.get(headerName);
}

/**
 * Sets a CSRF token cookie in the response
 */
export function setCsrfTokenCookie(options: {
  response: NextResponse;
  token: string;
  cookieName?: string;
  cookieOptions?: CsrfCookieOptions;
}): void {
  const {
    response,
    token,
    cookieName = "csrf-token",
    cookieOptions = {},
  } = options;

  const isProduction = process.env.NODE_ENV === "production";
  const finalCookieOptions = {
    httpOnly: cookieOptions.httpOnly ?? true,
    secure: cookieOptions.secure ?? isProduction,
    sameSite: (cookieOptions.sameSite ?? "strict") as "strict" | "lax" | "none",
    path: cookieOptions.path ?? "/",
    maxAge: cookieOptions.maxAge ?? 60 * 60 * 24,
  };

  response.cookies.set(cookieName, token, finalCookieOptions);
}

/**
 * Gets or creates a CSRF token for a request
 * @param request - The incoming request
 * @param cookieName - The name of the cookie
 * @returns The existing token or generates a new one if not found
 */
export function getOrCreateCsrfToken(
  request: NextRequest,
  cookieName: string = "csrf-token"
): string {
  const existingToken = getCsrfTokenFromCookie(request, cookieName);
  if (existingToken) {
    return existingToken;
  }
  return generateCSRFToken();
}

/**
 * Creates a CSRF protection middleware for Next.js
 * @param options - Configuration options for the middleware
 * @returns A middleware function that validates CSRF tokens
 */
export function createCsrfProtect(options: CsrfProtectOptions) {
  // Validate secret
  if (!options.secret) {
    throw new Error(
      "CSRF secret is required. Generate one with:\n" +
      "  node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\"\n" +
      "Then set it as CSRF_SECRET in your environment variables."
    );
  }

  if (options.secret.length < 32) {
    throw new Error(
      `CSRF secret must be at least 32 characters (base64 of 24+ bytes). Got ${options.secret.length} characters.\n` +
      "Generate a proper secret with:\n" +
      "  node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\""
    );
  }

  // Validate secret is valid base64
  try {
    base64ToBytes(options.secret);
  } catch {
    throw new Error(
      "CSRF secret must be valid base64. Generate one with:\n" +
      "  node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\""
    );
  }

  // Parse allowedOrigins (can be string or array)
  const allowedOriginsInput = options.allowedOrigins;
  const allowedOrigins = Array.isArray(allowedOriginsInput)
    ? allowedOriginsInput
    : typeof allowedOriginsInput === "string"
      ? parseAllowedOrigins(allowedOriginsInput)
      : [];

  // Validate allowedOrigins format
  for (const origin of allowedOrigins) {
    if (!origin.startsWith("http://") && !origin.startsWith("https://")) {
      throw new Error(
        `Invalid origin in allowedOrigins: "${origin}"\n` +
        `Origins must include protocol. Did you mean "https://${origin}"?`
      );
    }
    if (origin.endsWith("/")) {
      throw new Error(
        `Invalid origin in allowedOrigins: "${origin}"\n` +
        "Origins should not include trailing slash."
      );
    }
  }

  // Auto-detect production for secure cookies
  const isProduction = process.env.NODE_ENV === "production";

  const config = {
    cookie: {
      httpOnly: options.cookie?.httpOnly ?? true,
      secure: options.cookie?.secure ?? isProduction,
      sameSite: (options.cookie?.sameSite ?? "strict") as "strict" | "lax" | "none",
      path: options.cookie?.path ?? "/",
      maxAge: options.cookie?.maxAge ?? 60 * 60 * 24,
    },
    cookieName: options.cookieName ?? "csrf-token",
    headerName: options.headerName ?? "x-csrf-token",
    methods: options.pageMethods ?? ["POST", "PUT", "PATCH", "DELETE"],
    apiMethods: options.apiMethods ?? ["POST", "PUT", "PATCH", "DELETE"],
    secret: options.secret,
    ttlSeconds: options.ttlSeconds ?? 900,
    allowedSkewSeconds: options.allowedSkewSeconds ?? 60,
    allowedOrigins,
    tokenRotationGracePeriod: options.tokenRotationGracePeriod ?? 30,
  };

  // Validate sameSite: 'none' requires secure: true
  if (config.cookie.sameSite === "none" && !config.cookie.secure) {
    throw new Error(
      "Cookie sameSite='none' requires secure=true.\n" +
      "Either set cookie.secure=true or use sameSite='lax' or 'strict'."
    );
  }

  // Debug helper
  const debug = (message: string, data?: Record<string, any>) => {
    if (options.debug) {
      console.log(`[CSRF Debug] ${message}`, data || "");
    }
  };

  return async function csrfProtect(request: NextRequest, response: NextResponse): Promise<string> {
    debug(`${request.method} ${request.nextUrl.pathname}`, {
      origin: request.headers.get("origin"),
      referer: request.headers.get("referer"),
    });
    const { pathname } = request.nextUrl;
    const origin = request.headers.get("origin") ?? "";
    const referer = request.headers.get("referer") ?? "";
    const secFetchSite = request.headers.get("sec-fetch-site") ?? "";
    const accept = request.headers.get("accept") ?? "";
    const secFetchDest = request.headers.get("sec-fetch-dest") ?? "";
    const secFetchMode = request.headers.get("sec-fetch-mode") ?? "";
    const nextUrl = request.headers.get("next-url") ?? "";
    const sameOrigin = origin === request.nextUrl.origin;
    const refererOk = referer.startsWith(request.nextUrl.origin);
    let candidateOrigin = "";
    if (origin) {
      candidateOrigin = origin;
    } else if (referer) {
      try {
        candidateOrigin = new URL(referer).origin;
      } catch {
        // ignore parse errors
      }
    }

    // 1) Enforce CSRF on API and internal Next assets first
    if (pathname.startsWith("/_next") || pathname.startsWith("/api/")) {
      // Check if this is a cross-origin request from an allowed origin
      const isAllowedOrigin = candidateOrigin && config.allowedOrigins.includes(candidateOrigin);
      const isCrossOrigin = !sameOrigin && !refererOk;
      
      // Handle CORS preflight (OPTIONS) requests
      if (request.method === "OPTIONS") {
        debug("OPTIONS preflight request", { isCrossOrigin, isAllowedOrigin, candidateOrigin });
        if (isCrossOrigin && !isAllowedOrigin) {
          debug("❌ Blocked: Origin not in allowedOrigins", { origin: candidateOrigin, allowedOrigins: config.allowedOrigins });
          throw new CsrfError("Origin not allowed for CORS preflight");
        }
        
        // Set CORS headers for preflight
        if (isAllowedOrigin) {
          debug("✅ Setting CORS headers for allowed origin");
          response.headers.set("Access-Control-Allow-Origin", candidateOrigin);
          response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
          response.headers.set("Access-Control-Allow-Headers", `${config.headerName}, Content-Type, Authorization`);
          response.headers.set("Access-Control-Allow-Credentials", "true");
          response.headers.set("Access-Control-Max-Age", "86400");
        }
        
        debug("✅ OPTIONS request allowed");
        return "";
      }
      
      // For non-OPTIONS requests: enforce origin checks
      debug("Checking origin", { isCrossOrigin, isAllowedOrigin, candidateOrigin });
      if (isCrossOrigin && !isAllowedOrigin) {
        debug("❌ Blocked: Cross-origin request not allowed", { origin: candidateOrigin, allowedOrigins: config.allowedOrigins });
        throw new CsrfError("Cross-origin request blocked");
      }
      
      // Set CORS headers for allowed origins
      if (isAllowedOrigin) {
        response.headers.set("Access-Control-Allow-Origin", candidateOrigin);
        response.headers.set("Access-Control-Allow-Credentials", "true");
        response.headers.set("Vary", "Origin");
      }
      
      // For allowed origins, relax Fetch Metadata requirements (they may not be present in all browsers/clients)
      if (!isAllowedOrigin) {
        debug("Checking Fetch Metadata headers", { secFetchSite, secFetchMode, secFetchDest });
        // Only enforce strict Fetch Metadata for same-origin requests
        if (secFetchSite !== "same-origin" && secFetchSite !== "same-site" && secFetchSite !== "") {
          debug("❌ Blocked: Invalid Sec-Fetch-Site", { secFetchSite });
          throw new CsrfError("Invalid Sec-Fetch-Site header");
        }
        if (secFetchMode !== "cors" && secFetchMode !== "navigate" && secFetchMode !== "") {
          debug("❌ Blocked: Invalid Sec-Fetch-Mode", { secFetchMode });
          throw new CsrfError("Invalid Sec-Fetch-Mode header");
        }
        if (secFetchDest !== "empty" && secFetchDest !== "document" && secFetchDest !== "") {
          debug("❌ Blocked: Invalid Sec-Fetch-Dest", { secFetchDest });
          throw new CsrfError("Invalid Sec-Fetch-Dest header");
        }
        debug("✅ Fetch Metadata headers valid");
      } else {
        debug("Skipping Fetch Metadata checks for allowed origin");
      }
      
      // Disallow browsers attempting to navigate to API endpoints (except allowed origins)
      if (!isAllowedOrigin && accept.toLowerCase().includes("text/html")) {
        debug("❌ Blocked: HTML accept header for API endpoint", { accept });
        throw new CsrfError("Invalid accept header for API");
      }
      
      // For API routes, check CSRF only for methods in apiMethods config
      debug("Checking if method requires CSRF", { method: request.method, apiMethods: config.apiMethods });
      if (config.apiMethods.includes(request.method)) {
        debug("Method requires CSRF validation");
        const cookieValue = getCsrfTokenFromCookie(request, config.cookieName);
        const headerToken = getCsrfTokenFromHeader(request, config.headerName);

        debug("Checking tokens", { 
          hasHeaderToken: !!headerToken, 
          hasCookieToken: !!cookieValue,
          cookieTokenCount: cookieValue ? parseMultipleTokens(cookieValue).length : 0
        });

        if (!headerToken || !cookieValue) {
          debug("❌ Blocked: Missing CSRF token", { hasHeader: !!headerToken, hasCookie: !!cookieValue });
          throw new CsrfError("CSRF token is required");
        }

        // If secret present, validate with grace period support; else fallback to equality
        if (config.secret) {
          debug("Validating HMAC-signed tokens with grace period");
          const valid = await verifyTokenWithGracePeriod(
            cookieValue,
            headerToken,
            config.secret,
            config.ttlSeconds,
            config.allowedSkewSeconds
          );
          if (!valid) {
            debug("❌ Blocked: Token validation failed");
            throw new CsrfError("Invalid CSRF token");
          }
          debug("✅ Token validation passed");
        } else {
          // For non-signed tokens, just check equality (no grace period)
          if (!validateCSRFToken(headerToken, cookieValue)) {
            debug("❌ Blocked: Token mismatch");
            throw new CsrfError("Invalid CSRF token");
          }
          debug("✅ Token match confirmed");
        }

        // Return the first token from cookie (the current one)
        const cookieTokens = parseMultipleTokens(cookieValue);
        debug("✅ CSRF validation passed for API route");
        return cookieTokens[0] ?? "";
      }
      
      debug("Method does not require CSRF (safe method)");
      // For safe methods on API routes, return existing token or empty string
      const existing = getCsrfTokenFromCookie(request, config.cookieName);
      return existing ?? "";
    }

    // 2) For all other routes, skip CSRF for safe methods but issue a token (without rotating if already present)
    if (request.method === "GET" || request.method === "HEAD" || request.method === "OPTIONS") {
      // Only issue CSRF token cookie for real navigations to HTML documents from same-origin
      if ((sameOrigin || !origin) && accept.includes("text/html") && secFetchDest === "document") {
        if (config.secret) {
          return await getOrCreateSignedToken(
            request,
            response,
            config.cookieName,
            config.secret,
            config.cookie,
            config.ttlSeconds,
            config.allowedSkewSeconds
          );
        }
        const token = getOrCreateCsrfToken(request, config.cookieName);
        setCsrfTokenCookie({ response, token, cookieName: config.cookieName, cookieOptions: config.cookie });
        return token;
      }

      if (
        (sameOrigin || !origin) &&
        accept.includes("*/*") &&
        secFetchDest === "empty" &&
        nextUrl.length > 0
      ) {
        if (config.secret) {
          return await getOrCreateSignedToken(
            request,
            response,
            config.cookieName,
            config.secret,
            config.cookie,
            config.ttlSeconds,
            config.allowedSkewSeconds
          );
        }
        const token = getOrCreateCsrfToken(request, config.cookieName);
        setCsrfTokenCookie({ response, token, cookieName: config.cookieName, cookieOptions: config.cookie });
        return token;
      }
      // Non-document or cross-origin: do not set cookie, return empty token
      return "";
    }

    // 3) For non-API routes, validate only for modifying methods
    debug("Non-API route - checking if method requires CSRF", { method: request.method, pageMethods: config.methods });
    if (config.methods.includes(request.method)) {
      debug("Method requires CSRF validation for page route");
      const cookieValue = getCsrfTokenFromCookie(request, config.cookieName);
      const headerToken = getCsrfTokenFromHeader(request, config.headerName);

      if (!headerToken || !cookieValue) {
        debug("❌ Blocked: Missing CSRF token", { hasHeader: !!headerToken, hasCookie: !!cookieValue });
        throw new CsrfError("CSRF token is required");
      }

      if (config.secret) {
        debug("Validating HMAC-signed tokens");
        const valid = await verifyTokenWithGracePeriod(
          cookieValue,
          headerToken,
          config.secret,
          config.ttlSeconds,
          config.allowedSkewSeconds
        );
        if (!valid) {
          debug("❌ Blocked: Token validation failed");
          throw new CsrfError("Invalid CSRF token");
        }
        debug("✅ Token validation passed");
      } else {
        // For non-signed tokens, just check equality (no grace period)
        if (!validateCSRFToken(headerToken, cookieValue)) {
          debug("❌ Blocked: Token mismatch");
          throw new CsrfError("Invalid CSRF token");
        }
        debug("✅ Token match confirmed");
      }
      debug("✅ CSRF validation passed for page route");
    } else {
      debug("Method does not require CSRF (safe method)");
    }

    // Keep token stable for non-API routes as well; do not rotate here
    const existing = getCsrfTokenFromCookie(request, config.cookieName);
    if (existing) {
      return existing;
    }
    // If somehow missing, create one now
    if (config.secret) {
      return await getOrCreateSignedToken(
        request,
        response,
        config.cookieName,
        config.secret,
        config.cookie,
        config.ttlSeconds,
        config.allowedSkewSeconds
      );
    }
    const token = getOrCreateCsrfToken(request, config.cookieName);
    setCsrfTokenCookie({ response, token, cookieName: config.cookieName, cookieOptions: config.cookie });
    return token;
  };
}

/**
 * Rotates CSRF token and sets it in both the cookie and response header
 * Useful for auth flows (login/logout/refresh) where you want to rotate after state changes
 * Maintains a grace period where old tokens remain valid to prevent race conditions
 */
export async function rotateAndSetCsrfToken(options: {
  response: { cookies: NextResponse["cookies"]; headers: NextResponse["headers"] };
  secret: string;
  oldToken?: string | null;
  cookieName?: string;
  headerName?: string;
  cookieOptions?: CsrfCookieOptions;
  gracePeriod?: number;
}): Promise<string> {
  const {
    response,
    secret,
    oldToken = null,
    cookieName = "csrf-token",
    headerName = "X-CSRF-Token",
    cookieOptions = {},
    gracePeriod = 30,
  } = options;

  // Generate new token
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const tsBytes = u32ToBigEndianBytes(Math.floor(Date.now() / 1000));
  const toSign = new Uint8Array(nonceBytes.length + tsBytes.length);
  toSign.set(nonceBytes, 0);
  toSign.set(tsBytes, nonceBytes.length);
  const sig = await hmacSha256(toSign, base64ToBytes(secret));
  const newToken = `${toBase64Url(nonceBytes)}.${toBase64Url(tsBytes)}.${toBase64Url(sig)}`;

  // Parse old tokens and clean up expired ones
  const oldTokens = parseMultipleTokens(oldToken);
  const validOldTokens = await cleanupExpiredTokens(oldTokens, secret, gracePeriod);
  
  // Combine new token with valid old tokens (new token first)
  const allTokens = [newToken, ...validOldTokens];
  const combinedTokenValue = combineTokens(allTokens);

  const isProduction = process.env.NODE_ENV === "production";
  const finalCookieOptions = {
    httpOnly: cookieOptions.httpOnly ?? true,
    secure: cookieOptions.secure ?? isProduction,
    sameSite: (cookieOptions.sameSite ?? "strict") as "strict" | "lax" | "none",
    path: cookieOptions.path ?? "/",
    maxAge: cookieOptions.maxAge ?? 60 * 60 * 24,
  };

  // Set combined value in cookie (may contain multiple tokens)
  response.cookies.set(cookieName, combinedTokenValue, finalCookieOptions);
  // Set only new token in header
  response.headers.set(headerName, newToken);
  
  return newToken;
}

/**
 * Gets the CSRF token from the current request context
 * Automatically retrieves headers and cookies from Next.js and returns the token
 * @param cookieName - The name of the cookie (default: "csrf-token")
 * @param headerName - The name of the header (default: "X-CSRF-Token")
 * @returns The CSRF token or empty string if not found
 *
 * @example
 * ```tsx
 * export async function generateMetadata() {
 *   const csrfToken = await getCsrfTokenFromServer();
 *   return {
 *     other: {
 *       "x-csrf-token": csrfToken,
 *     },
 *   };
 * }
 * ```
 */
export async function getCsrfTokenFromServer(
  cookieName: string = "csrf-token",
  headerName: string = "X-CSRF-Token"
): Promise<string> {
  const { headers, cookies } = await import("next/headers");
  const hdrs = await headers();
  const cookieStore = await cookies();
  const headerToken = hdrs.get(headerName) ?? "";
  const cookieToken = cookieStore.get(cookieName)?.value ?? "";
  return headerToken || cookieToken;
}

/**
 * Wraps the CSRF protect middleware to handle Next.js middleware pattern
 * This automatically handles copying CSRF cookies from a temp response to the final response
 * @param csrfProtectFn - The CSRF protect function from createCsrfProtect
 * @param request - The incoming Next.js request
 * @param cookieName - The name of the cookie (default: "csrf-token")
 * @returns The CSRF token string and cookie value
 */
export async function handleCsrfProtection(
  csrfProtectFn: (request: NextRequest, response: NextResponse) => Promise<string>,
  request: NextRequest,
  cookieName: string = "csrf-token"
): Promise<{ token: string; cookieValue: string | null }> {
  const tempResponse = new NextResponse();
  const token = await csrfProtectFn(request, tempResponse);
  const csrfCookie = tempResponse.cookies.get(cookieName);
  return { token, cookieValue: csrfCookie?.value ?? null };
}

/**
 * Parses allowed origins from a comma-separated string
 * @param originsString - Comma-separated string of allowed origins
 * @returns Array of trimmed, non-empty origin strings
 */
function parseAllowedOrigins(originsString: string): string[] {
  return originsString
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

/**
 * Handles CSRF protection in Next.js middleware with automatic cookie and header setting
 * Handles errors internally and returns appropriate response
 * Can accept either a pre-created csrfProtect function or create one from config
 */
export async function handleCsrfInMiddleware(
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
): Promise<NextResponse> {
  const {
    request,
    response,
    cookieName = "csrf-token",
    headerName = "X-CSRF-Token",
    cookieOptions,
    onError,
  } = options;

  // Create csrfProtect if config provided instead of function
  let csrfProtect: (request: NextRequest, response: NextResponse) => Promise<string>;
  if ("csrfProtect" in options && options.csrfProtect) {
    csrfProtect = options.csrfProtect;
  } else {
    // Create from config
    csrfProtect = createCsrfProtect(options as CsrfProtectOptions);
  }

  try {
    const { token, cookieValue } = await handleCsrfProtection(csrfProtect, request, cookieName);

    // Set token in response headers for HTML document requests
    const accept = request.headers.get("accept") ?? "";
    const secFetchDest = request.headers.get("sec-fetch-dest") ?? "";
    if (token && accept.includes("text/html") && secFetchDest === "document") {
      response.headers.set(headerName, token);
    }

    // Copy the CSRF cookie value if it was set
    if (cookieValue) {
      const isProduction = process.env.NODE_ENV === "production";
      const finalCookieOptions = {
        httpOnly: cookieOptions?.httpOnly ?? true,
        secure: cookieOptions?.secure ?? isProduction,
        sameSite: (cookieOptions?.sameSite ?? "strict") as "strict" | "lax" | "none",
        path: cookieOptions?.path ?? "/",
        maxAge: cookieOptions?.maxAge ?? 60 * 60 * 24,
      };
      response.cookies.set(cookieName, cookieValue, finalCookieOptions);
    }

    return response;
  } catch (err) {
    if (err instanceof CsrfError) {
      // Allow custom error handler or use default 403
      if (onError) {
        return onError(err);
      }
      return new NextResponse("Forbidden", { status: 403 });
    }
    // Re-throw non-CSRF errors
    throw err;
  }
}

