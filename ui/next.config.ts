import type { NextConfig } from "next";

// The UI proxies /backend/* to the NDR API so browser traffic stays same-origin
// (httpOnly session cookie, no CORS). In Docker Compose the API is reachable
// at http://ndr-api:8080 via the internal network.
const backend =
  process.env.BACKEND_INTERNAL_URL || "http://ndr-api:8080";

const nextConfig: NextConfig = {
  output: "standalone",
  // deterministic workspace root -> .next/standalone/server.js
  turbopack: { root: process.cwd() },
  async rewrites() {
    return [
      {
        source: "/backend/:path*",
        destination: `${backend}/:path*`,
      },
    ];
  },
};

export default nextConfig;
