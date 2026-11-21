import type { MetadataRoute } from "next";
import { publicSiteOrigin } from "@/lib/web-runtime.mjs";

export const dynamic = "force-dynamic";

export default function robots(): MetadataRoute.Robots {
  const origin = publicSiteOrigin();
  if (!origin) return { rules: { userAgent: "*", disallow: "/" } };
  return {
    rules: {
      userAgent: "*",
      allow: ["/", "/api/media/file/"],
      disallow: ["/admin", "/api/", "/manage", "/vpn", "/mcp"],
    },
    sitemap: new URL("/sitemap.xml", origin).href,
  };
}
