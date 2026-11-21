import { getPayload } from "payload";
import config from "@payload-config";
import {
  isLoopbackRequest,
  personalGatewayEnabled,
  webRuntimeRole,
} from "@/lib/web-runtime.mjs";

export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  const role = webRuntimeRole();
  if (
    !["workstation", "private"].includes(role) ||
    !isLoopbackRequest(request.headers, request.method)
  )
    return new Response(null, {
      status: 404,
      headers: { "Cache-Control": "no-store" },
    });
  const payload = await getPayload({ config });
  const result = await payload.count({
    collection: "articles",
    overrideAccess: false,
  });
  const execution = personalGatewayEnabled();
  return Response.json(
    {
      edition:
        role === "private"
          ? "rookstride-private-site"
          : "rookstride-local-preview",
      schema: 1,
      cms: "ready",
      publishedArticles: result.totalDocs,
      workerExecution: execution,
      personalGateway: execution,
      hostedWorkerExecution: false,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
