import type { Metadata } from "next";
import { publicSiteOrigin } from "./web-runtime.mjs";

const androidRepository = "https://github.com/VictorBoykoV/rookstride";
const androidTag = "v0.4.0-alpha6";
export const publicProjectLinks = {
  androidRepository,
  androidRelease: `${androidRepository}/releases/tag/${androidTag}`,
  androidApk: `${androidRepository}/releases/download/${androidTag}/rookstride-0.4.0-alpha6-universal.apk`,
  androidPairGuide: `${androidRepository}/blob/main/docs/PAIR-MODE.md`,
  singleGateway: "https://github.com/VictorBoykoV/single-vps-vpn-gateway",
  doubleGateway: "https://github.com/VictorBoykoV/two-hop-vpn-gateway",
};

export function publicPageMetadata(
  path: string,
  title: string,
  description: string,
  image?: string,
): Metadata {
  const origin = publicSiteOrigin();
  if (!origin) return { title, description };
  const url = new URL(path, origin);
  return {
    title,
    description,
    robots: { index: true, follow: true },
    alternates: { canonical: url },
    openGraph: {
      type: "website",
      siteName: "Rookstride",
      title,
      description,
      url,
      ...(image && { images: [new URL(image, origin)] }),
    },
  };
}
