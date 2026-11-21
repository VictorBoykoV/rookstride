export const indexableSitePaths = [
  "/",
  "/agents",
  "/comics",
  "/connect",
  "/downloads",
  "/journal",
  "/providers",
  "/self-hosted-vpn",
  "/start",
];
const discoveryPaths = new Set(["/robots.txt", "/sitemap.xml", "/llms.txt"]);
const publicPages = new Set([...indexableSitePaths, "/manage"]);
const loopbackHosts = new Set(["127.0.0.1:3100", "localhost:3100"]);
const safeMethods = new Set(["GET", "HEAD"]);

export function webRuntimeRole() {
  switch (process.env.ROOKSTRIDE_HOSTED_SITE) {
    case undefined:
      return "workstation";
    case "1":
      return "private";
    case "public":
      return "reader";
    default:
      return "disabled";
  }
}

export function personalGatewayEnabled() {
  return (
    webRuntimeRole() === "workstation" &&
    process.env.ROOKSTRIDE_PERSONAL_WEB === "1" &&
    process.getuid?.() !== 0
  );
}

export function configuredPublicOrigin() {
  const value = process.env.ROOKSTRIDE_PUBLIC_ORIGIN;
  if (!value) return;
  try {
    const url = new URL(value);
    if (url.protocol === "https:" && url.origin === value) return url;
  } catch {
    return;
  }
}

export function publicSiteOrigin() {
  if (webRuntimeRole() === "reader") return configuredPublicOrigin();
}

export function hostedPilotVisible() {
  return Boolean(
    publicSiteOrigin() && process.env.ROOKSTRIDE_HOSTED_VPN_PILOT === "1",
  );
}

/** @param {Request} request */
export function mcpBrowserRequest(request) {
  if (
    request.method !== "GET" ||
    ["mcp-protocol-version", "mcp-session-id", "last-event-id"].some((header) =>
      request.headers.has(header),
    )
  )
    return false;

  const accepted = new Set();
  for (const entry of (request.headers.get("accept") ?? "").split(",")) {
    const [type, ...parameters] = entry.toLowerCase().split(";");
    const quality = parameters.find((parameter) => /^\s*q\s*=/.test(parameter));
    const weight = quality ? Number(quality.split("=")[1]) : 1;
    if (weight > 0 && weight <= 1) accepted.add(type.trim());
  }
  return accepted.has("text/html") && !accepted.has("text/event-stream");
}

/** @param {Pick<Headers, "get">} headers @param {string} method */
export function isLoopbackRequest(headers, method) {
  const host = headers.get("host") || "";
  return (
    loopbackHosts.has(host) &&
    (safeMethods.has(method) ||
      method === "OPTIONS" ||
      headers.get("origin") === `http://${host}`)
  );
}

/** @param {string} segment */
export function isSafePathSegment(segment) {
  return (
    segment.length > 0 &&
    segment !== "." &&
    segment !== ".." &&
    !/[/%\\\u0000-\u001f\u007f]/.test(segment)
  );
}

/** @param {string} encodedPath @param {string} method */
export function publicReaderRoute(encodedPath, method) {
  if (encodedPath === "/mcp" && publicSiteOrigin())
    return ["GET", "POST", "DELETE"].includes(method);
  if (!safeMethods.has(method)) return false;
  let path;
  try {
    path = decodeURIComponent(encodedPath);
  } catch {
    return false;
  }
  if (path.split("/").some((part) => part === "." || part === ".."))
    return false;
  if (publicPages.has(path)) return true;
  if (discoveryPaths.has(path)) return Boolean(publicSiteOrigin());
  if (path === "/vpn") return hostedPilotVisible();
  const publication = path.match(/^\/(?:comics|journal)\/([^/]+)$/);
  if (publication) return isSafePathSegment(publication[1]);
  if (
    /^\/(?:brand\/(?:assistants\/)?[a-z0-9-]+\.(?:svg|webp)|licenses\/[A-Za-z0-9-]+\.txt)$/.test(
      path,
    )
  )
    return true;
  if (/^\/_next\/static\/[\w.()[\]/-]+\.(?:js|css|woff2?)$/.test(path))
    return true;
  const media = path.match(/^\/api\/media\/file\/([^/]+)$/);
  return Boolean(media && isSafePathSegment(media[1]));
}
