import { notFound } from "next/navigation";
import { ModuleLanguage } from "@/i18n/client";
import { HostedSetup } from "@/components/hosted-setup";
import { hostedPilotVisible } from "@/lib/web-runtime.mjs";
import "@/components/gateway-workspace.css";

export const dynamic = "force-dynamic";

export default function HostedVpnPage() {
  if (!hostedPilotVisible()) notFound();
  return (
    <ModuleLanguage scope="manage">
      <HostedSetup />
    </ModuleLanguage>
  );
}
