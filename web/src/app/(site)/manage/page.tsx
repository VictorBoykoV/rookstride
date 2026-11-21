import { PersonalWorkspace } from "@/components/personal-workspace";
import { SetupPreview } from "@/components/setup-preview";
import { personalGatewayEnabled } from "@/lib/web-runtime.mjs";

export default function Manage() {
  return personalGatewayEnabled() ? (
    <PersonalWorkspace />
  ) : (
    <SetupPreview />
  );
}
