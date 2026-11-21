import { previewMessages } from "@/i18n/en/management-status.mjs";
import { inspectExample } from "@/lib/preview.mjs";
import { isLoopbackRequest, webRuntimeRole } from "@/lib/web-runtime.mjs";

export async function POST(request: Request) {
  if (webRuntimeRole() !== "workstation")
    return new Response(null, {
      status: 404,
      headers: { "Cache-Control": "no-store" },
    });
  if (!isLoopbackRequest(request.headers, request.method))
    return Response.json({ error: previewMessages.localOnly }, { status: 403 });
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json(
      { error: previewMessages.jsonRequired },
      { status: 415 },
    );
  }
  const reader = request.body?.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  if (reader) {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > 1024) {
        await reader.cancel();
        return Response.json(
          { error: previewMessages.tooLarge },
          { status: 413 },
        );
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
  }
  try {
    return Response.json(inspectExample(JSON.parse(text)), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return Response.json(
      {
        error: previewMessages.invalidRequest,
      },
      { status: 400 },
    );
  }
}
