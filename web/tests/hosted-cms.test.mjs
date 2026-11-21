import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(import.meta.url);
const cli = fileURLToPath(new URL("../deploy/cms-state.mjs", import.meta.url));
const fixture = {
  title: "Hosted CMS trial",
  slug: "hosted-cms-trial",
  summary: "Check content and media recovery.",
  body: "A disposable acceptance fixture.",
  category: "project",
  publishedAt: "2026-11-19T00:00:00.000Z",
  _status: "published",
};
const identity = {
  email: "editor@example.invalid",
  password: process.env.ROOKSTRIDE_FIXTURE_PASSWORD,
};

if (process.argv[2]) {
  process.umask(0o077);
  const data = process.env.ROOKSTRIDE_DATA_DIR;
  process.env.PAYLOAD_SECRET = readFileSync(
    join(data, "payload-secret"),
    "utf8",
  );
  const { getPayload } = await import("payload");
  const { default: config } = await import("../src/payload.config.ts");
  const payload = await getPayload({ config });
  try {
    if (process.argv[2] === "write") {
      assert.equal(
        (await payload.find({ collection: "articles" })).totalDocs,
        0,
      );
      await payload.create({ collection: "users", data: identity });
      const { user } = await payload.login({
        collection: "users",
        data: identity,
      });
      const article = { collection: "articles", user, overrideAccess: false };
      await payload.create({ ...article, data: fixture });
      await payload.create({
        ...article,
        draft: true,
        data: { ...fixture, slug: "editor-only", _status: "draft" },
      });
      await payload.create({
        ...article,
        data: { ...fixture, slug: "preview-only", sampleContent: true },
      });
      const { default: sharp } = await import("sharp");
      const data = await sharp({
        create: { width: 3, height: 3, channels: 3, background: "#cc352f" },
      })
        .png()
        .toBuffer();
      const media = { collection: "media", user, overrideAccess: false };
      for (const publicApproved of [true, false]) {
        const name = publicApproved ? "approved.png" : "private.png";
        await payload.create({
          ...media,
          data: { alt: "Test image", publicApproved },
          file: { name, data, size: data.length, mimetype: "image/png" },
        });
      }
    } else {
      const { user, token } = await payload.login({
        collection: "users",
        data: identity,
      });
      assert.ok(token, "Editor login still works on the restored dataset");
      const readerRole = process.env.ROOKSTRIDE_HOSTED_SITE === "public";
      const result = await payload.find({
        collection: "articles",
        overrideAccess: false,
        ...(readerRole ? { user } : {}),
      });
      assert.deepEqual(
        result.docs.map((doc) => doc.slug),
        [fixture.slug],
      );
      const images = await payload.find({
        collection: "media",
        overrideAccess: false,
        ...(readerRole ? { user } : {}),
      });
      assert.deepEqual(
        images.docs.map((doc) => doc.filename),
        ["approved.png"],
      );
      if (readerRole) {
        await assert.rejects(
          payload.create({
            collection: "articles",
            overrideAccess: false,
            user,
            data: { ...fixture, slug: "reader-write" },
          }),
        );
      }
    }
  } finally {
    await payload.destroy();
  }
} else {
  test("hosted CMS migrates, keeps drafts and editor roles private, and restores content and uploads", () => {
    const scratch = mkdtempSync(join(tmpdir(), "rookstride-cms-test-"));
    const live = join(scratch, "live");
    const snapshot = join(scratch, "backup");
    const restored = join(scratch, "restored");
    const env = {
      ...process.env,
      NODE_ENV: "production",
      ROOKSTRIDE_HOSTED_SITE: "1",
      PAYLOAD_TELEMETRY_DISABLED: "1",
      PAYLOAD_DROP_DATABASE: "false",
      ROOKSTRIDE_FIXTURE_PASSWORD: randomBytes(24).toString("hex"),
    };
    function run(data, args, options = {}) {
      const result = spawnSync(process.execPath, args, {
        encoding: "utf8",
        timeout: 30000,
        env: { ...env, ROOKSTRIDE_DATA_DIR: data, ...options.env },
      });
      assert.ifError(result.error);
      assert.equal(
        result.status,
        options.status ?? 0,
        result.stderr || result.stdout,
      );
    }
    try {
      run(live, [cli, "check"], { status: 1 });
      run(live, [cli, "migrate"]);
      run(live, [cli, "migrate"]);
      run(live, [script, "write"]);
      run(live, [script, "verify"]);
      run(live, [cli, "backup", snapshot]);
      run(restored, [cli, "restore", snapshot]);
      run(restored, [cli, "restore", snapshot], { status: 1 });
      assert.deepEqual(
        readFileSync(join(restored, "media/approved.png")),
        readFileSync(join(live, "media/approved.png")),
      );
      run(restored, [script, "verify"], {
        env: { ROOKSTRIDE_HOSTED_SITE: "public" },
      });
      writeFileSync(join(snapshot, "media/approved.png"), "corrupted fixture");
      run(join(scratch, "damaged"), [cli, "restore", snapshot], { status: 1 });
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
}
