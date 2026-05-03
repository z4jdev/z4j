/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * When "true", the build was produced by `pnpm build:demo` and the
   * SPA loads the in-browser mock-fetch interceptor at
   * src/lib/api.demo.ts instead of talking to a real backend. Used
   * by the demo.z4j.dev deployment. See DEMO-Z4J-DEV-DESIGN.md.
   */
  readonly VITE_Z4J_DEMO_MODE?: string;

  /**
   * Override for the FastAPI brain URL during local dev. Read by
   * vite.config.ts to wire the dev-server proxy. Not used in
   * production builds (the brain serves the SPA from its own origin).
   */
  readonly VITE_BRAIN_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
