// Test setup file for CSRF library tests

// Mock crypto for consistent testing
if (typeof globalThis.crypto === "undefined") {
  // @ts-expect-error - Mocking crypto
  globalThis.crypto = {
    getRandomValues: (arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256);
      }
      return arr;
    },
    subtle: {
      importKey: jest.fn(),
      sign: jest.fn(),
    },
  } as any;
}
