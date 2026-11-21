import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { getLanguage, getMessages } from "@/i18n/messages";
import { createPreviewMcp } from "@/lib/preview-mcp.mjs";
import { mcpBrowserRequest, publicSiteOrigin } from "@/lib/web-runtime.mjs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const responseHeaders = {
  "Cache-Control": "no-store",
  Vary: "Accept, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID",
};

function browserPage(site: URL) {
  const copy = getMessages("site");
  const language = getLanguage("site");
  const mcp = copy.mcpLanding;
  const entities: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
  };
  const html = (text: string) =>
    text.replace(/[&<>"]/g, (char) => entities[char]);
  return new Response(
    `<!doctype html>
<html lang="${html(language.tag)}" dir="${html(language.dir)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>${html(mcp.title)} – ${html(copy.shell.wordmark)}</title>
  <link rel="icon" href="/brand/rook.svg" type="image/svg+xml">
  <style>
    body {
      background: #f5f6f8;
      color: #141418;
      font: 1rem/1.6 system-ui, sans-serif;
      margin: 0;
    }
    main {
      box-sizing: border-box;
      max-width: 44rem;
      margin: clamp(24px, 9vh, 100px) auto;
      padding: clamp(24px, 6vw, 48px);
      background: white;
      border: 1px solid #dcdde1;
      border-radius: 14px;
    }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: .6rem;
      color: inherit;
      font-weight: 700;
      text-decoration: none;
    }
    h1 {
      font-size: clamp(2rem, 5vw, 2.8rem);
      line-height: 1.12;
      letter-spacing: -.035em;
      margin: 1.6rem 0 .8rem;
    }
    p { max-width: 54ch; margin: 0 0 1.25rem; }
    .endpoint {
      background: #f5f6f8;
      padding: 1rem;
      border-radius: 8px;
    }
    .endpoint span { display: block; font-size: .86rem; font-weight: 650; }
    code { overflow-wrap: anywhere; }
    .setup {
      display: inline-flex;
      align-items: center;
      min-height: 44px;
      box-sizing: border-box;
      padding: .6rem 1.1rem;
      border-radius: 7px;
      background: #a91f31;
      color: white;
      font-weight: 650;
      text-decoration: none;
    }
    .setup:hover, .setup:focus-visible { background: #841727; }
    a:focus-visible { outline: 2px solid #a91f31; outline-offset: 4px; }
    .scope { font-size: .94rem; color: #494d57; margin: 1rem 0 0; }
    @media (max-width: 46rem) {
      main { margin-inline: 16px; }
    }
  </style>
</head>
<body>
  <main>
    <a class="brand" href="/"><img src="/brand/rook.svg" width="28" height="28" alt="">${html(copy.shell.wordmark)}</a>
    <h1>${html(mcp.title)}</h1>
    <p>${html(mcp.intro)}</p>
    <p class="endpoint"><span>${html(mcp.endpoint)}</span><code dir="ltr">${html(new URL("/mcp", site).href)}</code></p>
    <a class="setup" href="/agents">${html(mcp.setup)}</a>
    <p class="scope">${html(mcp.practice)}</p>
  </main>
</body>
</html>`,
    {
      headers: {
        ...responseHeaders,
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy":
          "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        "X-Robots-Tag": "noindex, nofollow",
      },
    },
  );
}

async function handle(request: Request) {
  const site = publicSiteOrigin();
  const origin = request.headers.get("origin");
  if (!site) return new Response(null, { status: 404 });
  if (
    request.headers.get("host") !== site.host ||
    (origin && origin !== site.origin)
  )
    return new Response(null, { status: 403 });
  if (mcpBrowserRequest(request)) return browserPage(site);
  const transport = new WebStandardStreamableHTTPServerTransport({
    enableJsonResponse: true,
    maxRequestBodySize: 8192,
  });
  const server = createPreviewMcp();
  try {
    await server.connect(transport);
    const response = await transport.handleRequest(request);
    for (const [name, value] of Object.entries(responseHeaders))
      response.headers.set(name, value);
    return response;
  } finally {
    await server.close();
  }
}

export const POST = handle;
export const GET = handle;
export const DELETE = handle;
