import { withPayload } from "@payloadcms/next/withPayload";

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
