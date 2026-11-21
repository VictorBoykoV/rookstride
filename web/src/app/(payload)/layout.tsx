import config from "@payload-config";
import "@payloadcms/next/css";
import { RootLayout, handleServerFunctions } from "@payloadcms/next/layouts";
import type { ServerFunctionClient } from "payload";
import type { ReactNode } from "react";
import { importMap } from "./admin/importMap.js";
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { isLoopbackRequest, webRuntimeRole } from "@/lib/web-runtime.mjs";

const serverFunction: ServerFunctionClient = async (args) => {
  "use server";
  if (
    !["workstation", "private"].includes(webRuntimeRole()) ||
    !isLoopbackRequest(await headers(), "POST")
  )
    notFound();
  return handleServerFunctions({ ...args, config, importMap });
};

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <RootLayout
      config={config}
      importMap={importMap}
      serverFunction={serverFunction}
    >
      {children}
    </RootLayout>
  );
}
