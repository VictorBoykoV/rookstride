import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, mkdtemp, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { androidRelease } from "../src/lib/android-release.mjs";

const [, , publicDirectory, localApk] = process.argv;
if (!publicDirectory || process.argv.length > 4)
  throw new Error("Provide a public directory and optionally a local copy of the released APK.");

const { bytes, filename, github, sha256 } = androidRelease.arm64;
const destination = join(publicDirectory, "downloads");
await mkdir(destination, { recursive: true });
const temporary = await mkdtemp(join(destination, ".apk-"));
try {
  const staged = join(temporary, filename);
  let source;
  if (localApk) {
    source = createReadStream(localApk);
  } else {
    const response = await fetch(github, { signal: AbortSignal.timeout(180_000) });
    if (!response.ok || !response.body)
      throw new Error(`GitHub APK download returned HTTP ${response.status}.`);
    source = Readable.fromWeb(response.body);
  }
  const hash = createHash("sha256");
  let length = 0;
  const verify = new Transform({
    transform(chunk, encoding, done) {
      length += chunk.length;
      if (length > bytes) return done(new Error("The released APK exceeds its recorded size."));
      hash.update(chunk);
      done(null, chunk);
    },
  });
  await pipeline(source, verify, createWriteStream(staged, { mode: 0o644 }));
  if (length !== bytes || hash.digest("hex") !== sha256)
    throw new Error("The APK does not match the recorded release.");
  await rename(staged, join(destination, filename));
  console.log(`Verified ${filename} (${length} bytes).`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
