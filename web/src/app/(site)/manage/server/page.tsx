import { getMessages } from "@/i18n/messages";
import { ServerSetup } from "@/components/server-setup";
import { personalGatewayEnabled } from "@/lib/web-runtime.mjs";
import { redirect } from "next/navigation";

const text = getMessages("manage").frame;
export const metadata = {
  title: text.serverTitle,
  description: text.serverDescription,
};

export default function ServerPage() {
  if (!personalGatewayEnabled()) redirect("/manage#practice");
  return <ServerSetup />;
}
