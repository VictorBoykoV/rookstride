import { getMessages } from "@/i18n/messages";
import { publicSiteOrigin } from "@/lib/web-runtime.mjs";
import { publicProjectLinks } from "@/lib/site-discovery";

const copy = getMessages("site").selfHosted;

export const dynamic = "force-dynamic";

export function GET() {
  const origin = publicSiteOrigin();
  if (!origin) return new Response(null, { status: 404 });
  const link = (path: string) => new URL(path, origin).href;
  const lines = [
    "# Rookstride",
    "",
    `> ${copy.lead}`,
    "",
    `- ${copy.one.body}`,
    `- ${copy.two.body} ${copy.two.details}`,
    `- ${copy.filter.body}`,
    `- ${copy.assistants.body}`,
    "",
    "## Public guides and downloads",
    "",
    `- [How Rookstride works](${link("/self-hosted-vpn")}): Diagrams and a comparison of routing, cost, DNS, performance and setup availability.`,
    `- [Get started](${link("/start")}): Browser pilot, Android and assistant options.`,
    `- [Device connection guide](${link("/connect")}): VPN client downloads, profile imports and IKEv2 settings for Android, iPhone, macOS and Windows.`,
    `- [Android downloads](${link("/downloads")}): ARM64 APK from Rookstride or GitHub, plus a universal APK and release notes.`,
    `- [Assistant setup](${link("/agents")}): Configure the read-only public MCP connector and learn about the local operator connector for ten single-server methods.`,
    `- [Android prerelease and source](${publicProjectLinks.androidRelease})`,
    `- [Single VPN Ubuntu gateway](${publicProjectLinks.singleGateway})`,
    `- [Double VPN Ubuntu gateway](${publicProjectLinks.doubleGateway})`,
    "",
  ];
  return new Response(lines.join("\n"), {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
