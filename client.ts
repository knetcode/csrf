"use client";

import { useSyncExternalStore } from "react";

/**
 * Installs a lightweight fetch interceptor that reads X-CSRF-Token from responses
 * and updates/creates the meta[name="x-csrf-token"] tag so subsequent requests
 * can send the latest token without a full navigation.
 */
export function installCsrfResponseInterceptor(): () => void {
  if (typeof window === "undefined") return () => undefined as unknown as void;
  const originalFetch = window.fetch;
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const res = await originalFetch(input, init);
    try {
      const newToken = res.headers.get("X-CSRF-Token");
      if (newToken) {
        let meta = document.querySelector<HTMLMetaElement>('meta[name="x-csrf-token"]');
        if (!meta) {
          meta = document.createElement("meta");
          meta.name = "x-csrf-token";
          document.head.appendChild(meta);
        }
        if (meta.content !== newToken) {
          meta.content = newToken;
          // Trigger a storage event to notify React consumers
          window.dispatchEvent(new StorageEvent("storage", { key: "csrf-token-update" }));
        }
      }
    } catch {
      // ignore
    }
    return res;
  };
  return () => {
    window.fetch = originalFetch;
  };
}

/**
 * React hook to retrieve the current CSRF token from the meta tag
 * Automatically subscribes to token updates from the response interceptor
 * @returns Object with csrfToken string
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { csrfToken } = useCsrfToken();
 *   // Use csrfToken in your fetch requests
 * }
 * ```
 */
export function useCsrfToken(): { csrfToken: string } {
  if (typeof document === "undefined") {
    return { csrfToken: "" };
  }

  const token = useSyncExternalStore(
    (onStoreChange) => {
      window.addEventListener("storage", onStoreChange);
      return () => window.removeEventListener("storage", onStoreChange);
    },
    () => {
      return document.querySelector<HTMLMetaElement>('meta[name="x-csrf-token"]')?.content ?? "";
    },
    () => "" // Server-side fallback
  );

  return { csrfToken: token };
}
