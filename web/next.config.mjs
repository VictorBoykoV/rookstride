import { withPayload } from "@payloadcms/next/withPayload";
import { androidRelease } from "./src/lib/android-release.mjs";

export default withPayload({
  agentRules: false,
  poweredByHeader: false,
  // Publish canonical and robots tags in the initial HTML for text-only readers.
  htmlLimitedBots: /.*/,
  output: "standalone",
  serverExternalPackages: ["ssh2"],
  experimental: { cpus: 1 },
  async headers() {
    return [
      {
        source: androidRelease.arm64.sitePath,
        headers: [
          { key: "Content-Type", value: "application/vnd.android.package-archive" },
          { key: "Content-Disposition", value: `attachment; filename="${androidRelease.arm64.filename}"` },
          { key: "Cache-Control", value: "public, max-age=86400" },
        ],
      },
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "X-Frame-Options", value: "DENY" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
        ],
      },
    ];
  },
});
