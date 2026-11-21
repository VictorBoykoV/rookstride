import type { Metadata } from "next";
import { androidRelease } from "./android-release.mjs";
import { publicSiteOrigin } from "./web-runtime.mjs";

const androidRepository = androidRelease.repository;
export const publicProjectLinks = {
  androidRepository,
  androidRelease: androidRelease.page,
  androidApk: androidRelease.arm64.sitePath,
  androidApkGitHub: androidRelease.arm64.github,
  androidApkUniversal: androidRelease.universal,
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
