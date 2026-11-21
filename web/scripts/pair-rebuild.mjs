import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { startWorker } from "../src/lib/gateway-service.mjs";
import {
  createPairRebuild,
  pairRebuildConfirmation,
  PairRebuildError,
  readPairRebuildInput,
} from "../src/lib/pair-rebuild.mjs";
import { maxPairRecoveryBytes } from "../src/lib/pair-recovery.mjs";

const [mode, directory, targetsFile, archiveFile, entry, exit] =
  process.argv.slice(2);
const actions = ["review", "start", "resume"];
const web = fileURLToPath(new URL("../", import.meta.url));

try {
  if (
    !actions.includes(mode) ||
    !archiveFile ||
    (mode === "review" ? !entry || !exit : entry || exit) ||
    process.env.ROOKSTRIDE_HOSTED_SITE !== undefined ||
    process.getuid() === 0
  )
    throw new PairRebuildError("invalid-command");
  if (process.stdin.isTTY) throw new PairRebuildError("use-protected-stdin");

  process.env.ROOKSTRIDE_PERSONAL_WEB = "1";
  const targets = JSON.parse(
    readPairRebuildInput(targetsFile).toString("utf8"),
  );
  const encrypted = readPairRebuildInput(archiveFile, maxPairRecoveryBytes);
  const rebuild = createPairRebuild({
    directory,
    openWorker: () => startWorker({ dir: web, reinstall: true }),
  });
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  try {
    const lines = input[Symbol.asyncIterator]();
    const { value: passphrase } = await lines.next();
    if (!passphrase) throw new PairRebuildError("archive-passphrase-required");
    if (mode === "review") {
      const review = await rebuild.review({
        targets,
        ubuntu: { entry, exit },
        encrypted,
        passphrase,
      });
      for (const [role, member] of Object.entries(review.members))
        console.log(
          role,
          member.ubuntu,
          member.boot,
          member.diskBytes,
          member.fingerprint,
          member.job,
        );
    } else {
      const { value: confirmation } = await lines.next();
      if (confirmation !== pairRebuildConfirmation)
        throw new PairRebuildError("explicit-rebuild-approval-required");
      let reported;
      const result = await rebuild.run({
        targets,
        encrypted,
        passphrase,
        confirmation,
        pauseAfterDispatch: mode === "start",
        resumeRestore: mode === "resume",
        onProgress({ role, state, stage }) {
          const message = [role, state, stage].filter(Boolean).join(" ");
          if (message && message !== reported) console.log(message);
          reported = message;
        },
      });
      console.log(result.state);
    }
  } finally {
    input.close();
  }
} catch (error) {
  console.error(
    [error.code ?? error.name, error.role, error.stage]
      .filter(Boolean)
      .join(" "),
  );
  process.exitCode = 1;
}
