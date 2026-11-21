import { createHash, randomBytes } from "node:crypto";
import {
  copyFileSync,
  createReadStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { backup, DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const release = realpathSync(fileURLToPath(new URL("..", import.meta.url)));
const migrations = fileURLToPath(new URL("migrations/", import.meta.url));
const steps = readdirSync(migrations)
  .filter((name) => /^\d{3}-[a-z0-9-]+\.sql$/.test(name))
  .sort();
if (
  !steps.length ||
  steps.some((name, i) => Number(name.slice(0, 3)) !== i + 1)
)
  throw new Error(
    "CMS migration files must be numbered consecutively from 001.",
  );

const database = "cms.sqlite";
const secretFile = "payload-secret";
const manifestFile = "cms-backup.json";

function outside(path, dir) {
  return path !== dir && !path.startsWith(`${dir}${sep}`);
}

function canonicalPath(path) {
  if (!path || !isAbsolute(path))
    throw new Error("Use an absolute directory path.");
  const full = resolve(path);
  return existsSync(full)
    ? realpathSync(full)
    : join(realpathSync(dirname(full)), basename(full));
}

export function statePath() {
  const data = canonicalPath(process.env.ROOKSTRIDE_DATA_DIR);
  if (!outside(data, release) || !outside(release, data))
    throw new Error("ROOKSTRIDE_DATA_DIR must be separate from the release.");
  return data;
}

function requirePrivate(path, directory = false) {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  const correctType = directory ? stat?.isDirectory() : stat?.isFile();
  if (!correctType || stat.mode & 0o077)
    throw new Error(`Missing or improperly protected CMS path: ${path}`);
}

function privateSecret(data) {
  const path = join(data, secretFile);
  requirePrivate(path);
  const secret = readFileSync(path, "utf8").trim();
  if (!/^[0-9a-f]{96}$/.test(secret))
    throw new Error("Invalid CMS secret file.");
  return secret;
}

function schema(db) {
  return db.prepare("PRAGMA user_version").get().user_version;
}

function checkDatabase(data, integrity = false) {
  const path = join(data, database);
  requirePrivate(path);
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    if (schema(db) !== steps.length)
      throw new Error(
        "CMS schema does not match this release. Run a reviewed migration or select the matching release.",
      );
    if (
      integrity &&
      db.prepare("PRAGMA quick_check").get().quick_check !== "ok"
    )
      throw new Error("CMS database integrity check failed.");
  } finally {
    db.close();
  }
}

export function readReadyState(data) {
  requirePrivate(data, true);
  requirePrivate(join(data, "media"), true);
  const secret = privateSecret(data);
  checkDatabase(data);
  return secret;
}

function migrate(data) {
  if (!existsSync(data)) mkdirSync(data, { mode: 0o700 });
  requirePrivate(data, true);
  const path = join(data, database);
  if (existsSync(path)) requirePrivate(path);
  else writeFileSync(path, "", { flag: "wx", mode: 0o600 });
  const db = new DatabaseSync(path);
  try {
    db.exec("BEGIN IMMEDIATE");
    const version = schema(db);
    if (version > steps.length)
      throw new Error("CMS schema is newer than this release.");
    if (
      version === 0 &&
      db
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' LIMIT 1")
        .get()
    )
      throw new Error(
        "Refusing to migrate an unversioned database. Import data through a reviewed migration.",
      );
    if (version > 0) privateSecret(data);
    for (let i = version; i < steps.length; i++) {
      db.exec(readFileSync(join(migrations, steps[i]), "utf8"));
      db.exec(`PRAGMA user_version = ${i + 1}`);
    }
    if (!existsSync(join(data, secretFile)))
      writeFileSync(join(data, secretFile), randomBytes(48).toString("hex"), {
        flag: "wx",
        mode: 0o600,
      });
    privateSecret(data);
    if (!existsSync(join(data, "media")))
      mkdirSync(join(data, "media"), { mode: 0o700 });
    requirePrivate(join(data, "media"), true);
    db.exec("COMMIT");
  } finally {
    db.close();
  }
}

async function hashes(data) {
  const names = readdirSync(join(data, "media")).sort();
  const paths = [database, secretFile, ...names.map((name) => `media/${name}`)];
  const results = [];
  for (const relative of paths) {
    const file = join(data, relative);
    requirePrivate(file);
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(file)) hash.update(chunk);
    results.push([relative, hash.digest("hex")]);
  }
  return results;
}

async function createDirectory(path, populate) {
  mkdirSync(path, { mode: 0o700 });
  try {
    mkdirSync(join(path, "media"), { mode: 0o700 });
    await populate();
  } catch (error) {
    rmSync(path, { recursive: true, force: true });
    throw error;
  }
}

async function snapshot(data, destination) {
  readReadyState(data);
  await createDirectory(destination, async () => {
    const db = new DatabaseSync(join(data, database), { readOnly: true });
    try {
      await backup(db, join(destination, database));
    } finally {
      db.close();
    }
    copyFileSync(join(data, secretFile), join(destination, secretFile));
    for (const name of readdirSync(join(data, "media"))) {
      const upload = join(data, "media", name);
      requirePrivate(upload);
      copyFileSync(upload, join(destination, "media", name));
    }
    checkDatabase(destination, true);
    writeFileSync(
      join(destination, manifestFile),
      JSON.stringify(
        {
          format: 1,
          files: await hashes(destination),
        },
        null,
        2,
      ) + "\n",
      { flag: "wx", mode: 0o600 },
    );
  });
}

async function restore(source, data) {
  readReadyState(source);
  const manifest = join(source, manifestFile);
  requirePrivate(manifest);
  const expected = JSON.parse(readFileSync(manifest, "utf8"));
  await createDirectory(data, async () => {
    for (const path of [database, secretFile])
      copyFileSync(join(source, path), join(data, path));
    for (const name of readdirSync(join(source, "media"))) {
      const upload = join(source, "media", name);
      requirePrivate(upload);
      copyFileSync(upload, join(data, "media", name));
    }
    if (
      expected.format !== 1 ||
      JSON.stringify(await hashes(data)) !== JSON.stringify(expected.files)
    )
      throw new Error("CMS backup manifest verification failed.");
    checkDatabase(data, true);
  });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href
) {
  process.umask(0o077);
  try {
    const [action, path, ...extra] = process.argv.slice(2);
    const data = statePath();
    if (
      extra.length ||
      !["migrate", "check", "backup", "restore"].includes(action) ||
      Boolean(path) !== ["backup", "restore"].includes(action)
    )
      throw new Error(
        "Use cms-state.mjs migrate, check, backup <absolute directory>, or restore <absolute directory>.",
      );
    if (action === "migrate") migrate(data);
    if (action === "check") readReadyState(data);
    if (path) {
      const location = canonicalPath(path);
      if (
        !outside(location, data) ||
        !outside(data, location) ||
        !outside(location, release)
      )
        throw new Error(
          "CMS backup must be separate from the release and active state.",
        );
      if (action === "backup") await snapshot(data, location);
      else await restore(location, data);
    }
    console.log(`CMS ${action} complete (schema ${steps.length}).`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
