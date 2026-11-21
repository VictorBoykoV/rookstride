import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import { GatewayFrame } from "@/components/gateway-frame";
import { getMessages } from "@/i18n/messages";
import { ModuleLanguage } from "@/i18n/client";
import { personalGatewayEnabled } from "@/lib/web-runtime.mjs";
import "@/components/gateway-workspace.css";

export const dynamic = "force-dynamic";
export function generateMetadata(): Metadata {
  const text = getMessages("manage").frame;
  return {
    title: personalGatewayEnabled() ? text.metadataTitle : text.practice,
  };
}
export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  interactiveWidget: "resizes-content",
};

export default function ManageLayout({ children }: { children: ReactNode }) {
  return (
    <ModuleLanguage scope="manage">
      <GatewayFrame personal={personalGatewayEnabled()}>
        {children}
      </GatewayFrame>
    </ModuleLanguage>
  );
}
