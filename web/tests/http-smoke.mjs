import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

const base = new URL(
  process.env.ROOKSTRIDE_TEST_URL || "http://127.0.0.1:3100",
);
if (base.hostname !== "127.0.0.1" || base.protocol !== "http:")
  throw new Error("This test is limited to a loopback development instance.");
let passed = 0;
async function request(route, options = {}) {
  return fetch(new URL(route, base), {
    ...options,
    signal: AbortSignal.timeout(45000),
  });
}
function pass(label) {
  passed++;
  console.log(`PASS ${label}`);
}
const status = await request("/api/local-status").then((r) => r.json());
assert.equal(status.edition, "rookstride-local-preview");
assert.equal(status.cms, "ready");
assert.equal(status.hostedWorkerExecution, false);
assert.equal(status.personalGateway, true);
assert.equal(status.workerExecution, true);
pass("personal workstation mode and local content database");

for (const route of [
  "/",
  "/manage",
  "/manage/server",
  "/start",
  "/self-hosted-vpn",
  "/providers",
  "/agents?client=cursor",
  "/agents?client=constructor",
  "/agents",
  "/journal",
  "/journal/a-little-more-control",
  "/comics",
  "/downloads",
  "/admin",
]) {
  const response = await request(route);
  assert.equal(response.status, 200, route);
  assert.ok((await response.text()).length > 1000);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  pass(`page ${route}`);
}
const homeHtml = await request("/").then((r) => r.text());
assert.ok(homeHtml.includes('href="/agents"'));
const heroStart = homeHtml.indexOf('aria-labelledby="home-title"');
const optionsStart = homeHtml.indexOf('id="setup-options"');
const guideStart = homeHtml.indexOf('aria-labelledby="setup-guide-title"');
const ownershipStart = homeHtml.indexOf('aria-labelledby="ownership-heading"');
assert.ok(
  heroStart >= 0 && optionsStart > heroStart && guideStart > optionsStart,
);
const hero = homeHtml.slice(heroStart, optionsStart);
assert.match(hero, /href="#setup-options">Set up your VPN/);
assert.equal((hero.match(/<a /g) || []).length, 1);
assert.ok(
  hero.includes('id="how-it-works"') && hero.includes('data-mode="single"'),
);
assert.ok(hero.includes("pay them directly"));
const homeOptions = homeHtml.slice(optionsStart, guideStart);
for (const [page, title] of [
  ["manage", "Web browser"],
  ["downloads", "Android phone"],
  ["agents", "AI assistant"],
]) {
  const row = homeOptions.match(
    new RegExp(`<a[^>]*href="/${page}"[^>]*>([\\s\\S]*?)</a>`),
  )?.[1];
  assert.ok(row?.includes(`<h3>${title}</h3>`) && row.includes("<svg"));
}
assert.equal((homeOptions.match(/<a /g) || []).length, 6);
assert.ok(homeOptions.includes('href="/self-hosted-vpn"'));
assert.ok(
  homeOptions.includes('href="/manage#practice"') &&
    homeOptions.includes('href="/connect"'),
);
assert.match(homeHtml, /<title>Rookstride – Build your own VPN<\/title>/);
assert.match(
  homeHtml,
  /<link\b(?=[^>]*\brel="icon")(?=[^>]*\bhref="\/brand\/rook\.svg")[^>]*>/,
);
assert.ok(ownershipStart > guideStart);
assert.ok(
  homeHtml.indexOf('src="/brand/rook-bridge-team.webp"') > ownershipStart,
);
assert.ok(homeHtml.includes("Filter out ads and trackers"));
assert.ok(homeHtml.includes('href="/comics#rook-origin"'));
assert.ok(
  (await request("/comics").then((r) => r.text())).includes('id="rook-origin"'),
);
assert.equal(
  (await request("/comics/missing-chapter-for-local-check")).status,
  404,
);
const bridge = await request("/brand/rook-bridge-team.webp");
assert.equal(bridge.status, 200);
assert.match(bridge.headers.get("content-type"), /image\/webp/);
pass(
  "homepage opens with setup and the interactive route, then the bridge-building illustration links to Rook’s origin",
);
const setupGuide = homeHtml.match(
  /<section[^>]*aria-labelledby="setup-guide-title"[^>]*>([\s\S]*?)<\/section>/,
)?.[1];
assert.ok(setupGuide && !/<button|<details/.test(setupGuide));
assert.equal((setupGuide.match(/data-art="rook-setup-map"/g) || []).length, 1);
assert.ok(!setupGuide.includes("rook-character rook-"));
assert.equal((setupGuide.match(/<h3>/g) || []).length, 4);
pass("one Rook illustration guides four visible setup steps");
const guide = await request("/self-hosted-vpn").then((r) => r.text());
assert.match(guide, /<h1>How Rookstride works<\/h1>/);
assert.match(guide, /aria-label="How a one-server VPN connects"/);
assert.match(guide, /aria-label="How a two-server VPN connects"/);
assert.match(guide, /<table aria-labelledby="route-comparison">/);
assert.match(guide, /Double VPN on two servers/);
assert.match(guide, /Fewer ads and trackers with DNS filtering/);
assert.match(guide, /name="robots" content="noindex, nofollow"/);
const localRobots = await request("/robots.txt").then((r) => r.text());
assert.match(localRobots, /Disallow: \/\s*$/);
assert.equal((await request("/llms.txt")).status, 404);
assert.doesNotMatch(
  await request("/sitemap.xml").then((r) => r.text()),
  /<loc>/,
);
pass("the setup guide renders locally while preview indexing remains disabled");
const providerHtml = await request("/providers").then((r) => r.text());
for (const [html, mode] of [
  [homeHtml, "single"],
  [providerHtml, "two"],
]) {
  const map = html.match(
    /<figure class="network-flow[^>]*>([\s\S]*?)<\/figure>/,
  )?.[1];
  assert.ok(map, "A connected diagram is present");
  assert.ok(
    map.indexOf('class="diagram-key"') > map.indexOf('data-point="internet"'),
  );
  const hiddenSlot = mode === "single" ? "exit" : "single";
  assert.match(
    map,
    new RegExp(`<span[^>]*data-slot="${hiddenSlot}"[^>]*aria-hidden="true"`),
  );
  const buttons = [...map.matchAll(/<button[^>]*>/g)].map(([button]) => button);
  const points = ["device", "entry", "filter", "internet"];
  if (mode === "two") points.push("exit");
  for (const point of points) {
    assert.equal(
      buttons.filter(
        (button) =>
          button.includes(`data-point="${point}"`) &&
          button.includes('aria-haspopup="dialog"'),
      ).length,
      1,
      `One keyboard target for ${point} across both layouts`,
    );
  }
  for (const leg of ["direct", "intended"]) {
    const paths = [
      ...map.matchAll(new RegExp(`data-leg="${leg}" d="([^"]+)"`, "g")),
    ].map((match) => match[1]);
    assert.equal(paths.length, 2);
    assert.ok(
      paths.some((d) => /^M[\d. ]+H[\d.]+$/.test(d)),
      "straight horizontal path",
    );
    assert.ok(
      paths.some((d) => /^M[\d. ]+V[\d.]+$/.test(d)),
      "straight vertical path",
    );
  }
  assert.ok(map.includes("<dialog") && !map.includes('href="https://'));
}
pass(
  "both route maps expose the explorable points and explanations for the displayed server count",
);
for (const path of [
  "/brand/assistants/cursor-cube.svg",
  "/brand/assistants/gemini-cli.svg",
]) {
  const response = await request(path);
  assert.equal(response.status, 200);
  assert.ok(response.headers.get("content-type").includes("image/svg+xml"));
  const svg = await response.text();
  assert.ok(svg.includes("<svg") && !svg.includes("<script"));
}
const agentsHtml = await request("/agents").then((r) => r.text());
for (const client of ["codex", "claude-code"]) {
  const path = `/brand/assistants/${client}.webp`;
  const response = await request(path);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /image\/webp/);
  assert.ok(agentsHtml.includes(`src="${path}"`));
}
pass("assistant picker shows the local Codex and Claude Code marks");
assert.ok(agentsHtml.includes("mcp-preview.mjs"));
assert.ok(agentsHtml.includes("mcp_servers.rookstride-preview"));
assert.ok(
  agentsHtml.includes(
    "Compatibility with each installed app still needs its own check.",
  ),
);
pass(
  "visible agent route, real local connector configuration and honest qualification",
);
const startHtml = await request("/start").then((r) => r.text());
for (const href of ["/downloads", "/manage", "/agents"])
  assert.ok(startHtml.includes(`href="${href}"`));
assert.ok(startHtml.includes("Planned"));
const cursorHtml = await request("/agents?client=cursor").then((r) => r.text());
const headingText = (html) =>
  [...html.matchAll(/<h2[^>]*>([\s\S]*?)<\/h2>/g)].map((m) =>
    m[1]
      .replace(/<!--[\s\S]*?-->|<[^>]*>/g, "")
      .replace(/\s+/g, " ")
      .trim(),
  );
assert.ok(headingText(cursorHtml).includes("Connect Rookstride to Cursor."));
for (const query of ["client=constructor", "client=cursor&client=gemini"]) {
  const fallbackHtml = await request(`/agents?${query}`).then((r) => r.text());
  assert.ok(headingText(fallbackHtml).includes("Connect Rookstride to Codex."));
}
pass(
  "Get started choices, honest Telegram state and allowlisted assistant links",
);
assert.equal((await request("/journal/no-such-local-article")).status, 404);
pass("unpublished/missing article has a real 404");

const anonymousArticles = await request("/api/articles?draft=true").then((r) =>
  r.json(),
);
assert.equal(
  anonymousArticles.docs.some((d) => d._status !== "published"),
  false,
);
assert.equal(
  anonymousArticles.docs.some((d) => d.slug === "unpublished-local-draft"),
  false,
);
pass("drafts remain private even with draft=true");
assert.ok([401, 403].includes((await request("/api/users")).status));
assert.ok(
  [401, 403].includes(
    (
      await request("/api/articles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      })
    ).status,
  ),
);
pass("anonymous user listing and editorial mutation are denied");

const endpoint = "/api/preview/inspect";
const headers = { "Content-Type": "application/json", Origin: base.origin };
for (const scenario of ["fresh", "existing", "unreachable", "changed-key"]) {
  const response = await request(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify({ address: "192.0.2.10", scenario }),
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.mode, "fixture");
  assert.equal(body.serverContacted, false);
  assert.equal(body.executionAvailable, false);
  if (scenario !== "fresh") assert.deepEqual(body.steps, []);
  assert.equal(response.headers.get("cache-control"), "no-store");
  pass(`explicitly non-executing ${scenario} example`);
}
for (const [body, expected] of [
  [JSON.stringify({ address: "127.0.0.1", scenario: "fresh" }), 400],
  [
    JSON.stringify({
      address: "192.0.2.10",
      scenario: "fresh",
      password: "example-secret-marker",
    }),
    400,
  ],
  ["{bad-json", 400],
  ["x".repeat(1200), 413],
]) {
  const response = await request(endpoint, { method: "POST", headers, body });
  assert.equal(response.status, expected);
  assert.equal(
    (await response.text()).includes("example-secret-marker"),
    false,
  );
}
pass(
  "real addresses, secret-shaped fields, malformed and oversized requests are rejected without echo",
);
assert.equal(
  (
    await request(endpoint, {
      method: "POST",
      headers: { ...headers, Origin: "https://example.invalid" },
      body: "{}",
    })
  ).status,
  403,
);
assert.equal(
  (
    await request(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    })
  ).status,
  403,
);
pass("foreign or missing browser origins are denied");

const gatewayHeaders = {
  ...headers,
  Authorization: "Bearer " + "A".repeat(43),
};
assert.equal(
  (await request("/api/gateway", { headers: gatewayHeaders })).status,
  401,
);
for (const action of [
  "profile",
  "guests",
  "grant",
  "install",
  "revoke",
  "close",
]) {
  const response = await request("/api/gateway", {
    method: "POST",
    headers: gatewayHeaders,
    body: JSON.stringify({ action }),
  });
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
}
pass(
  "personal profile, guest list, install and maintenance actions require the inspected session",
);
for (const [body, code] of [
  [
    {
      action: "inspect",
      address: "127.0.0.1",
      sshPort: 22,
      fingerprint: "SHA256:" + "A".repeat(43),
      password: "test-only",
    },
    400,
  ],
  [
    {
      action: "inspect",
      address: "192.0.2.7",
      sshPort: 22,
      fingerprint: "SHA256:" + "A".repeat(43),
      password: "test-only",
    },
    400,
  ],
  [{ action: "inspect", padding: "x".repeat(2300) }, 413],
]) {
  const r = await request("/api/gateway", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  assert.equal(r.status, code);
  assert.ok(!(await r.text()).includes("test-only"));
}
pass(
  "reserved targets and oversize input are refused before SSH without reflecting passwords",
);
assert.equal(
  (
    await request("/api/gateway", {
      method: "POST",
      headers: { ...headers, Origin: "https://example.invalid" },
      body: "{}",
    })
  ).status,
  403,
);
pass("personal gateway rejects a foreign browser origin");
const init = await request("/api/users/init").then((r) => r.json());
assert.equal(
  (
    await request("/api/users/first-register", {
      method: "POST",
      headers: { ...headers, Origin: "https://example.invalid" },
      body: "{}",
    })
  ).status,
  403,
);
pass("foreign-origin editor bootstrap is blocked");
if (init.initialized) {
  console.log(
    "NOT RUN editorial round trip: preserve the existing local editor account.",
  );
} else {
  let token, userId, articleId, mediaId, chapterId;
  try {
    const registration = await request("/api/users/first-register", {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: "local-check@example.invalid",
        password: randomBytes(32).toString("base64url"),
      }),
    });
    assert.equal(registration.status, 200, "local first-editor registration");
    const account = await registration.json();
    token = account.token;
    userId = account.user.id;
    assert.ok(token);
    assert.ok(userId);
    const auth = { ...headers, Authorization: `JWT ${token}` };
    const slug = `local-publication-check-${randomBytes(6).toString("hex")}`;
    const draft = await request("/api/articles?draft=true", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        title: "Temporary local publication check",
        slug,
        summary: "Disposable local editorial check.",
        body: "A local test, not a public announcement.",
        category: "project",
        publishedAt: new Date().toISOString(),
        sampleContent: true,
        _status: "draft",
      }),
    });
    assert.equal(draft.status, 201);
    articleId = (await draft.json()).doc.id;
    assert.equal((await request(`/journal/${slug}`)).status, 404);
    pass("editor draft is stored but cannot be read publicly");
    assert.equal(
      (
        await request(`/api/articles/${articleId}`, {
          method: "PATCH",
          headers: auth,
          body: JSON.stringify({ _status: "published" }),
        })
      ).status,
      200,
    );
    assert.equal((await request(`/journal/${slug}`)).status, 200);
    pass("explicit editor publication appears on the website");
    const storySlug = `atlas-check-${randomBytes(6).toString("hex")}`;
    const storyPath = `/comics/${storySlug}`;
    const upload = new FormData();
    const pixel = Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGN4Z2ABAANmAVfiY3egAAAAAElFTkSuQmCC",
      "base64",
    );
    upload.set(
      "file",
      new Blob([pixel], { type: "image/png" }),
      storySlug + ".png",
    );
    upload.set(
      "_payload",
      JSON.stringify({ alt: "Temporary page for reader verification." }),
    );
    const uploaded = await request("/api/media", {
      method: "POST",
      headers: { Authorization: auth.Authorization, Origin: base.origin },
      body: upload,
    });
    assert.equal(uploaded.status, 201);
    const media = (await uploaded.json()).doc;
    mediaId = media.id;
    const mediaPath = `/api/media/file/${encodeURIComponent(media.filename)}`;
    assert.equal((await request(mediaPath)).status, 403);
    const chapter = await request("/api/chapters", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        title: "Temporary chapter check",
        slug: storySlug,
        series: "Local fixture",
        summary: "Temporary reader check.",
        editorialApproved: true,
        pages: [{ image: mediaId, caption: "An approved page caption." }],
        _status: "published",
      }),
    });
    assert.equal(chapter.status, 201);
    chapterId = (await chapter.json()).doc.id;
    assert.equal((await request(storyPath)).status, 404);
    assert.ok(!(await request("/").then((r) => r.text())).includes(storyPath));
    const approveMedia = await request(`/api/media/${mediaId}`, {
      method: "PATCH",
      headers: auth,
      body: JSON.stringify({ publicApproved: true }),
    });
    assert.equal(approveMedia.status, 200);
    const storyHome = await request("/").then((r) => r.text());
    assert.ok(
      storyHome.indexOf('id="story-title"') >
        storyHome.indexOf('id="ownership-heading"'),
    );
    assert.ok(storyHome.includes(`href="${storyPath}"`));
    const storyResponse = await request(storyPath);
    assert.equal(storyResponse.status, 200);
    const storyHtml = await storyResponse.text();
    assert.ok(storyHtml.includes("An approved page caption."));
    const file = storyHtml.match(
      /<img[^>]*src="(\/api\/media\/file\/[^"]+)"/,
    )?.[1];
    assert.equal(file, mediaPath);
    const imageResponse = await request(file);
    assert.equal(imageResponse.status, 200);
    assert.deepEqual(Buffer.from(await imageResponse.arrayBuffer()), pixel);
    const unpublish = await request(`/api/chapters/${chapterId}`, {
      method: "PATCH",
      headers: auth,
      body: JSON.stringify({ editorialApproved: false }),
    });
    assert.equal(unpublish.status, 200);
    assert.equal((await request(storyPath)).status, 404);
    assert.ok(!(await request("/").then((r) => r.text())).includes(storyPath));
    const withdrawMedia = await request(`/api/media/${mediaId}`, {
      method: "PATCH",
      headers: auth,
      body: JSON.stringify({ publicApproved: false }),
    });
    assert.equal(withdrawMedia.status, 200);
    assert.equal((await request(mediaPath)).status, 403);
    pass("optional stories and direct media requests honor editorial approval");
    const denied = await request("/api/users", {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: "blocked-check@example.invalid",
        password: randomBytes(24).toString("hex"),
      }),
    });
    assert.equal(denied.status, 403);
    pass("anonymous editor enrollment is denied after the first local account");
  } finally {
    if (token) {
      const auth = { ...headers, Authorization: `JWT ${token}` };
      for (const [collection, id] of [
        ["chapters", chapterId],
        ["media", mediaId],
      ]) {
        if (id)
          assert.equal(
            (
              await request(`/api/${collection}/${id}`, {
                method: "DELETE",
                headers: auth,
              })
            ).status,
            200,
          );
      }
      if (articleId)
        assert.equal(
          (
            await request(`/api/articles/${articleId}`, {
              method: "DELETE",
              headers: auth,
            })
          ).status,
          200,
        );
      if (userId)
        assert.equal(
          (
            await request(`/api/users/${userId}`, {
              method: "DELETE",
              headers: auth,
            })
          ).status,
          200,
        );
    }
  }
  assert.equal(
    (await request("/api/users/init").then((r) => r.json())).initialized,
    false,
  );
  pass(
    "temporary editorial records/account removed; first-editor setup restored",
  );
}
console.log(
  `Completed ${passed} local HTTP checks. No SSH connection or deployment was performed.`,
);
