import { redirect } from "next/navigation";
import { PairInspection } from "@/components/pair-inspection";
import { getMessages } from "@/i18n/messages";
import { personalGatewayEnabled } from "@/lib/web-runtime.mjs";

export const metadata = { title: getMessages("manage").pair.title };

export default function PairPage() {
  if (!personalGatewayEnabled()) redirect("/manage#practice");
  return <PairInspection />;
}
