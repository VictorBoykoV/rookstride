import config from "@payload-config";
import { RootPage, generatePageMetadata } from "@payloadcms/next/views";
import { importMap } from "../importMap.js";
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { isLoopbackRequest, webRuntimeRole } from "@/lib/web-runtime.mjs";

type Args = {
  params: Promise<{ segments: string[] }>;
  searchParams: Promise<Record<string, string | string[]>>;
};
async function requireEditorPage() {
  if (
    !["workstation", "private"].includes(webRuntimeRole()) ||
    !isLoopbackRequest(await headers(), "GET")
  )
    notFound();
}

export async function generateMetadata({ params, searchParams }: Args) {
  await requireEditorPage();
  return generatePageMetadata({ config, params, searchParams });
}
export default async function Page({ params, searchParams }: Args) {
  await requireEditorPage();
  return RootPage({ config, params, searchParams, importMap });
}
