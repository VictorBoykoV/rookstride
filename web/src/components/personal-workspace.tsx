"use client";

import { useMessages } from "@/i18n/client";
import { SetupPreview } from "./setup-preview";
import { ServerSetup } from "./server-setup";
import { useWorkspaceMode } from "./gateway-frame";

export function PersonalWorkspace() {
  const text = useMessages("manage").frame;
  const mode = useWorkspaceMode();
  if (mode === null)
    return (
      <p className="gateway-loading" role="status">
        {text.opening}
      </p>
    );
  return mode === "practice" ? <SetupPreview /> : <ServerSetup />;
}
