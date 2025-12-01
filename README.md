# @lib/csrf

CSRF protection for Next.js with HMAC-signed tokens and React hooks.

## Setup

### 1. Generate Secret

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Add to `.env.local`:
```bash
CSRF_SECRET="your-generated-secret"
```

### 2. Middleware

```typescript
// src/middleware.ts
import { createCsrfProtect, handleCsrfInMiddleware } from "@lib/csrf/server";

const csrfProtect = createCsrfProtect({
  secret: process.env.CSRF_SECRET!,
});

export async function middleware(request) {
  const response = NextResponse.next();
  return await handleCsrfInMiddleware({ csrfProtect, request, response });
}
```

**Or even simpler (pass config directly):**

```typescript
export async function middleware(request) {
  const response = NextResponse.next();
  return await handleCsrfInMiddleware({
    secret: process.env.CSRF_SECRET!,
    request,
    response,
  });
}
```

### 3. Root Layout

```typescript
// src/app/layout.tsx
import { getCsrfTokenFromServer } from "@lib/csrf/server";

export async function generateMetadata() {
  return {
    other: { "x-csrf-token": await getCsrfTokenFromServer() },
  };
}
```

### 4. Client

```typescript
// src/app/layout.tsx (add to client component)
"use client";
import { installCsrfResponseInterceptor } from "@lib/csrf/client";
import { useEffect } from "react";

export function ClientLayout({ children }) {
  useEffect(() => installCsrfResponseInterceptor(), []);
  return children;
}
```

### 5. Usage

```typescript
"use client";
import { useCsrfToken } from "@lib/csrf/client";

export function MyForm() {
  const { csrfToken } = useCsrfToken();
  
  const submit = () => fetch("/api/endpoint", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify({ data }),
  });
  
  return <button onClick={submit}>Submit</button>;
}
```

## Configuration

### CORS (Cross-Origin Requests)

Allow specific origins to access your API:

```typescript
createCsrfProtect({
  secret: process.env.CSRF_SECRET!,
  allowedOrigins: ["https://app.example.com"], // Or comma-separated string
});
```

- Handles OPTIONS preflight automatically
- Sets CORS headers (`Access-Control-Allow-*`)
- CSRF tokens still required for protected methods

### Protect GET Requests

By default, GET requests don't require CSRF tokens (should be read-only). To protect GET:

```typescript
createCsrfProtect({
  secret: process.env.CSRF_SECRET!,
  apiMethods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
});
```

**Warning:** This breaks direct browser navigation and external API clients.

### Token Rotation

Rotate tokens after auth changes (login/logout/refresh):

```typescript
// In your auth route
const oldToken = request.cookies.get("csrf-token")?.value;
await rotateAndSetCsrfToken({
  response,
  secret: process.env.CSRF_SECRET!,
  oldToken,
});
```

Old tokens remain valid for 30 seconds (grace period) to prevent race conditions.

```typescript
await rotateAndSetCsrfToken({
  response,
  secret: process.env.CSRF_SECRET!,
  oldToken: request.cookies.get("csrf-token")?.value,
  gracePeriod: 30,  // Optional: seconds
});
```

### Debug Mode

Enable debug logging to see why requests are blocked:

```typescript
createCsrfProtect({
  secret: process.env.CSRF_SECRET!,
  debug: true,  // Logs validation steps to console
});
```

Output example:
```
[CSRF Debug] POST /api/user { origin: 'https://example.com', referer: null }
[CSRF Debug] Checking origin { isCrossOrigin: true, isAllowedOrigin: false }
[CSRF Debug] ❌ Blocked: Cross-origin request not allowed
```

## How It Works

### Why Cookie AND Header?

CSRF protection uses **both** a cookie and a header for defense-in-depth:

**Cookie alone isn't enough:**
- Browsers automatically send cookies with every request
- Attacker's site can trigger requests → cookies are sent → vulnerable to CSRF

**Header alone isn't enough:**
- XSS attacks can read headers and forge requests
- No server-side validation of token authenticity

**Cookie + Header together:**
1. Token is stored in httpOnly cookie (JavaScript can't read it)
2. Same token must be sent in request header (requires JavaScript)
3. Attacker can't read cookie (httpOnly) and can't send header (cross-origin)
4. Even if attacker tricks victim into clicking malicious link, header won't be sent

**Plus HMAC signing:**
- Each token is cryptographically signed
- Has timestamp (TTL: 15 minutes default)
- Can't be forged without secret key
- Automatic expiration

### When to Rotate Tokens

**Always rotate after:**
- ✅ Login
- ✅ Logout  
- ✅ Token refresh
- ✅ Password change
- ✅ Role/permission changes

**Example (auth routes):**
```typescript
// After successful login
const oldToken = request.cookies.get("csrf-token")?.value;
await rotateAndSetCsrfToken(response, env.CSRF_SECRET, "csrf-token", "X-CSRF-Token", {}, oldToken);
```

**Why rotation matters:**
Prevents token fixation attacks where attacker sets victim's token to known value before authentication.

### Browser Compatibility

**Modern browsers (recommended):**
- Chrome 76+
- Firefox 90+
- Safari 15.4+
- Edge 79+

**Required features:**
- `crypto.subtle` API (HMAC signing)
- Fetch Metadata headers (`Sec-Fetch-*`)
- `SameSite` cookie attribute

**Older browsers:**
Will be blocked due to strict Fetch Metadata requirements. This is intentional for security.

**Non-browser clients:**
- ✅ Works: Modern HTTP clients that send proper headers
- ❌ Blocked: cURL, Postman (by design - only your frontend should call your API)
- ✅ Works: Mobile apps if configured to send CSRF headers

## Troubleshooting

### "CSRF token is required"

**Cause:** Token missing from cookie or header

**Solutions:**
1. Check `installCsrfResponseInterceptor()` is called on client
2. Verify middleware is running
3. Check cookies aren't being blocked (browser settings, HTTPS)
4. Enable `debug: true` to see which token is missing

### "Cross-origin request blocked"

**Cause:** Request from origin not in `allowedOrigins`

**Solutions:**
1. Add origin to `allowedOrigins` config
2. Check origin includes protocol: `https://example.com` not `example.com`
3. Verify `Access-Control-Allow-Origin` header is set correctly
4. Enable `debug: true` to see detected origin

### "Invalid CSRF token"

**Causes:**
- Token expired (default TTL: 15 minutes)
- Token from different session
- Token was rotated and grace period expired
- Clock skew between client/server

**Solutions:**
1. Check server time is correct
2. Increase `tokenRotationGracePeriod` if race conditions
3. Increase `ttlSeconds` if tokens expire too quickly
4. Check if token rotation is happening correctly after auth
5. Enable `debug: true` to see validation details

### "Invalid Sec-Fetch-Site header"

**Cause:** Browser not sending Fetch Metadata or invalid value

**Solutions:**
1. Upgrade to modern browser (see Browser Compatibility)
2. This is intentional - older browsers are blocked for security
3. Check if browser extensions are interfering

### Tokens not updating

**Cause:** Response interceptor not installed or working

**Solutions:**
1. Verify `installCsrfResponseInterceptor()` is called in root layout
2. Check browser console for errors
3. Verify server sends `X-CSRF-Token` header in responses
4. Check if other fetch interceptors are conflicting

## API

### `createCsrfProtect(options)`

```typescript
const csrfProtect = createCsrfProtect({
  secret: process.env.CSRF_SECRET!,             // Required
  allowedOrigins?: ["https://example.com"],     // Or "url1,url2"
  apiMethods?: ["POST", "PUT", "PATCH", "DELETE"],
  pageMethods?: ["POST", "PUT", "PATCH", "DELETE"],
  cookieName?: "csrf-token",
  headerName?: "x-csrf-token",
  ttlSeconds?: 900,
  tokenRotationGracePeriod?: 30,
  debug?: false,                                 // Enable debug logging
  cookie?: { secure?: true, sameSite?: "strict" },
});
```

### Other Functions

**`handleCsrfInMiddleware(options)`**
Apply CSRF protection in middleware. Handles errors internally, returns NextResponse.

```typescript
// With pre-created csrfProtect
return await handleCsrfInMiddleware({ csrfProtect, request, response });

// Or pass config directly
return await handleCsrfInMiddleware({ secret: env.CSRF_SECRET, request, response });

// Custom error handling
return await handleCsrfInMiddleware({
  csrfProtect,
  request,
  response,
  onError: (err) => new NextResponse(err.message, { status: 403 }),
});
```

**`rotateAndSetCsrfToken({ response, secret, oldToken? })`**
Rotate token after login/logout. Pass `oldToken` for grace period support.

**`getCsrfTokenFromServer()`**
Get token in server components.

**`useCsrfToken()`** (Client)
React hook for CSRF token.

**`installCsrfResponseInterceptor()`** (Client)
Auto-update tokens from responses.