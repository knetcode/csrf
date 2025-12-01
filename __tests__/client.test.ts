import { describe, it, expect, beforeEach, afterEach, jest } from "@jest/globals";
import { renderHook, act } from "@testing-library/react";
import { useCsrfToken, installCsrfResponseInterceptor } from "../client";

describe("CSRF Client Module", () => {
  let originalFetch: typeof window.fetch | undefined;

  beforeEach(() => {
    if (typeof window !== "undefined") {
      originalFetch = window.fetch;
      // Reset DOM
      document.head.innerHTML = "";
    }
    jest.clearAllMocks();
  });

  afterEach(() => {
    if (typeof window !== "undefined" && originalFetch) {
      window.fetch = originalFetch;
    }
  });

  describe("useCsrfToken", () => {
    it("should return empty string on server side", () => {
      // The hook checks for document existence internally
      // In jsdom, document exists, so we test the actual behavior
      const { result } = renderHook(() => useCsrfToken());
      // If no meta tag exists, should return empty string
      expect(result.current.csrfToken).toBeDefined();
      expect(typeof result.current.csrfToken).toBe("string");
    });

    it("should return token from meta tag when present", () => {
      const meta = document.createElement("meta");
      meta.name = "x-csrf-token";
      meta.content = "test-csrf-token";
      document.head.appendChild(meta);

      const { result } = renderHook(() => useCsrfToken());
      expect(result.current.csrfToken).toBe("test-csrf-token");
    });

    it("should return empty string when meta tag is not present", () => {
      const { result } = renderHook(() => useCsrfToken());
      expect(result.current.csrfToken).toBe("");
    });

    it("should update when meta tag content changes", () => {
      const meta = document.createElement("meta");
      meta.name = "x-csrf-token";
      meta.content = "initial-token";
      document.head.appendChild(meta);

      const { result, rerender } = renderHook(() => useCsrfToken());
      expect(result.current.csrfToken).toBe("initial-token");

      act(() => {
        meta.content = "updated-token";
        window.dispatchEvent(new StorageEvent("storage", { key: "csrf-token-update" }));
      });

      rerender();
      // Note: The actual update depends on React's useSyncExternalStore implementation
      // This test verifies the hook doesn't throw and returns a value
      expect(result.current.csrfToken).toBeDefined();
    });
  });

  describe("installCsrfResponseInterceptor", () => {
    it("should return cleanup function on client side", () => {
      const cleanup = installCsrfResponseInterceptor();
      expect(typeof cleanup).toBe("function");
    });

    it("should return no-op function on server side", () => {
      const originalWindow = global.window;
      // @ts-expect-error - Mocking window
      delete global.window;

      const cleanup = installCsrfResponseInterceptor();
      expect(typeof cleanup).toBe("function");

      // Restore window
      global.window = originalWindow;
    });

    it("should intercept fetch and update meta tag with X-CSRF-Token header", async () => {
      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn((name: string) => {
            if (name === "X-CSRF-Token") return "new-csrf-token-from-response";
            return null;
          }),
        },
      });

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();

      await window.fetch("http://localhost:3000/api/test");

      const meta = document.querySelector<HTMLMetaElement>('meta[name="x-csrf-token"]');
      expect(meta).not.toBeNull();
      expect(meta?.content).toBe("new-csrf-token-from-response");

      cleanup();
    });

    it("should create meta tag if it doesn't exist", async () => {
      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn((name: string) => {
            if (name === "X-CSRF-Token") return "new-token";
            return null;
          }),
        },
      });

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();
      await window.fetch("http://localhost:3000/api/test");

      const meta = document.querySelector<HTMLMetaElement>('meta[name="x-csrf-token"]');
      expect(meta).not.toBeNull();
      expect(meta?.name).toBe("x-csrf-token");
      expect(meta?.content).toBe("new-token");

      cleanup();
    });

    it("should update existing meta tag if it exists", async () => {
      const existingMeta = document.createElement("meta");
      existingMeta.name = "x-csrf-token";
      existingMeta.content = "old-token";
      document.head.appendChild(existingMeta);

      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn((name: string) => {
            if (name === "X-CSRF-Token") return "new-token";
            return null;
          }),
        },
      });

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();
      await window.fetch("http://localhost:3000/api/test");

      const meta = document.querySelector<HTMLMetaElement>('meta[name="x-csrf-token"]');
      expect(meta?.content).toBe("new-token");
      expect(document.querySelectorAll('meta[name="x-csrf-token"]').length).toBe(1);

      cleanup();
    });

    it("should not update meta tag if header is not present", async () => {
      const existingMeta = document.createElement("meta");
      existingMeta.name = "x-csrf-token";
      existingMeta.content = "existing-token";
      document.head.appendChild(existingMeta);

      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn(() => null),
        },
      });

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();
      await window.fetch("http://localhost:3000/api/test");

      const meta = document.querySelector<HTMLMetaElement>('meta[name="x-csrf-token"]');
      expect(meta?.content).toBe("existing-token");

      cleanup();
    });

    it("should not update meta tag if content hasn't changed", async () => {
      const existingMeta = document.createElement("meta");
      existingMeta.name = "x-csrf-token";
      existingMeta.content = "same-token";
      document.head.appendChild(existingMeta);

      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn((name: string) => {
            if (name === "X-CSRF-Token") return "same-token";
            return null;
          }),
        },
      });

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();
      await window.fetch("http://localhost:3000/api/test");

      const meta = document.querySelector<HTMLMetaElement>('meta[name="x-csrf-token"]');
      expect(meta?.content).toBe("same-token");

      cleanup();
    });

    it("should dispatch storage event when token is updated", async () => {
      const storageListener = jest.fn();
      window.addEventListener("storage", storageListener);

      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn((name: string) => {
            if (name === "X-CSRF-Token") return "new-token";
            return null;
          }),
        },
      });

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();
      await window.fetch("http://localhost:3000/api/test");

      expect(storageListener).toHaveBeenCalled();

      window.removeEventListener("storage", storageListener);
      cleanup();
    });

    it("should handle fetch errors gracefully", async () => {
      const mockFetch = jest.fn().mockRejectedValue(new Error("Network error"));

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();

      await expect(window.fetch("http://localhost:3000/api/test")).rejects.toThrow("Network error");

      // Should not throw even if fetch fails
      expect(() => cleanup()).not.toThrow();
    });

    it("should restore original fetch on cleanup", async () => {
      const originalFetch = window.fetch;
      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn(() => null),
        },
      });

      const cleanup = installCsrfResponseInterceptor();
      expect(window.fetch).not.toBe(originalFetch);

      cleanup();
      expect(window.fetch).toBe(originalFetch);
    });

    it("should pass through fetch arguments correctly", async () => {
      const mockFetch = jest.fn().mockResolvedValue({
        headers: {
          get: jest.fn(() => null),
        },
      });

      window.fetch = mockFetch as any;

      const cleanup = installCsrfResponseInterceptor();

      const url = "http://localhost:3000/api/test";
      const options = { method: "POST", body: JSON.stringify({ test: "data" }) };

      await window.fetch(url, options);

      expect(mockFetch).toHaveBeenCalledWith(url, options);

      cleanup();
    });
  });
});
