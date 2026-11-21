import config from "@payload-config";
import {
  REST_DELETE,
  REST_GET,
  REST_OPTIONS,
  REST_PATCH,
  REST_POST,
  REST_PUT,
} from "@payloadcms/next/routes";
import {
  isLoopbackRequest,
  isSafePathSegment,
  webRuntimeRole,
} from "@/lib/web-runtime.mjs";

function restrict(handler: ReturnType<typeof REST_GET>, readMedia = false) {
  return async (request: Request, args: Parameters<typeof handler>[1]) => {
    const role = webRuntimeRole();
    if (role === "reader" && readMedia) {
      const { slug } = await args.params;
      if (
        slug?.length === 3 &&
        slug[0] === "media" &&
        slug[1] === "file" &&
        isSafePathSegment(slug[2])
      )
        return handler(request, args);
    }
    if (
      (role === "workstation" || role === "private") &&
      isLoopbackRequest(request.headers, request.method)
    )
      return handler(request, args);
    return new Response(null, {
      status: 404,
      headers: { "Cache-Control": "no-store" },
    });
  };
}

export const GET = restrict(REST_GET(config), true);
export const POST = restrict(REST_POST(config));
export const DELETE = restrict(REST_DELETE(config));
export const PATCH = restrict(REST_PATCH(config));
export const PUT = restrict(REST_PUT(config));
export const OPTIONS = restrict(REST_OPTIONS(config));
