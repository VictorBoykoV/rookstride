import { gatewayHeaders, handleGateway } from "@/lib/gateway-http.mjs";
import { gatewayMessages } from "@/i18n/en/management-status.mjs";
import { createGatewayService } from "@/lib/gateway-service.mjs";
import { createWorkbenchPair } from "@/lib/workbench-pair.mjs";
import {
  isLoopbackRequest,
  personalGatewayEnabled,
} from "@/lib/web-runtime.mjs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const server = globalThis as typeof globalThis & {
  personalGateway?: ReturnType<typeof createGatewayService>;
};
async function handle(request: Request) {
  if (!personalGatewayEnabled())
    return new Response(null, { status: 404, headers: gatewayHeaders });
  if (!isLoopbackRequest(request.headers, request.method))
    return Response.json(
      {
        messageKey: "localOriginRequired",
        message: gatewayMessages.localOriginRequired,
      },
      { status: 403, headers: gatewayHeaders },
    );
  return handleGateway(
    request,
    (server.personalGateway ??= createGatewayService(undefined, undefined, {
      pairPreflight: true,
      pairFactory: (options) => createWorkbenchPair({ ...options, allowMixedExits: true }),
      ubuntuReinstall: true,
      scopedAdministration: true,
    })),
  );
}
export const GET = handle;
export const POST = handle;
