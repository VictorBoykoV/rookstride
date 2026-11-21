import { gatewayMessages } from "../i18n/en/management-status.mjs";
import { GatewayError, isGatewayError } from "./gateway-service.mjs";

export const gatewayHeaders = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};
export async function handleGateway(request, service) {
  try {
    const token = request.headers
      .get("authorization")
      ?.match(/^Bearer ([A-Za-z0-9_-]{43})$/)?.[1];
    if (request.method === "GET")
      return Response.json(service.get(token), { headers: gatewayHeaders });
    if (
      request.headers.get("content-type")?.split(";")[0].trim() !==
      "application/json"
    )
      throw new GatewayError(415, "jsonRequired");
    const reader = request.body?.getReader();
    if (!reader) throw new GatewayError(400, "requestRequired");
    const limit = request.headers.get("X-Rookstride-Recovery") === "1"
      ? service.requestLimit?.(token) ?? 2048
      : 2048;
    const chunks = [];
    let length = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.length;
      if (length > limit) {
        await reader.cancel();
        throw new GatewayError(413, "requestTooLarge");
      }
      chunks.push(part.value);
    }
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      throw new GatewayError(400, "unreadableRequest");
    }
    if (length > 2048 && (typeof body?.action !== "string" ||
        (service.requestLimit?.(token, body.action) ?? 2048) < length))
      throw new GatewayError(413, "requestTooLarge");
    const result = await service.post(body, token);
    if (result && "recovery" in result) {
      return new Response(result.recovery, {
        headers: {
          ...gatewayHeaders,
          "Content-Type": "application/octet-stream",
          "Content-Disposition": 'attachment; filename="rookstride-owner-recovery.rookrec"',
        },
      });
    }
    if (result && "profile" in result) {
      return new Response(JSON.stringify(result.profile), {
        headers: {
          ...gatewayHeaders,
          "Content-Type": "application/octet-stream",
          "Content-Disposition": 'attachment; filename="rookstride.sswan"',
        },
      });
    }
    if (result && "configuration" in result) {
      return new Response(result.configuration + "\n", {
        headers: {
          ...gatewayHeaders,
          "Content-Type": "application/octet-stream",
          "Content-Disposition": `attachment; filename="${result.filename}"`,
        },
      });
    }
    return Response.json(result, { headers: gatewayHeaders });
  } catch (err) {
    const known = isGatewayError(err);
    return Response.json(
      {
        messageKey: known ? err.messageKey : "serviceUnavailable",
        message: known ? err.message : gatewayMessages.serviceUnavailable,
      },
      { status: known ? err.status : 503, headers: gatewayHeaders },
    );
  }
}
