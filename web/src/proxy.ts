import { NextResponse, type NextRequest } from "next/server";
import {
  isLoopbackRequest,
  publicReaderRoute,
  webRuntimeRole,
} from "@/lib/web-runtime.mjs";

export function proxy(request: NextRequest) {
  const role = webRuntimeRole();
  const path = request.nextUrl.pathname;
  if (
    role === "disabled" ||
    (role === "reader" && !publicReaderRoute(path, request.method))
  ) {
    return new NextResponse(null, {
      status: 404,
      headers: { "Cache-Control": "no-store" },
    });
  }
  const operatorPath = /^\/(?:admin|api)(?:\/|$)/.test(path);
  if (
    (role === "private" || (role === "workstation" && operatorPath)) &&
    !isLoopbackRequest(request.headers, request.method)
  )
    return NextResponse.json(
      { error: "Open the operator site through its local connection." },
      { status: 403, headers: { "Cache-Control": "no-store" } },
    );
  return NextResponse.next();
}

export const config = { matcher: "/:path*" };
