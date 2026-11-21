import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { isAbsolute, join } from "node:path";
import { readServerRecord, readUbuntuRecovery } from "./gateway-input.mjs";

const owner = process.getuid();
const terminalOriginal = ["failed", "cancelled", "expired"];

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function matchesUbuntuJob(record, candidate) {
  return Boolean(
    record && candidate && same(record, readUbuntuRecovery(candidate)),
  );
}

export function hostedServerMatches(server, candidate) {
  return (
    candidate?.address === server.address &&
    candidate.sshPort === server.sshPort &&
    candidate.fingerprint === server.fingerprint &&
    candidate.keyType === server.keyType
  );
}

export function replacementServer(recovery) {
  return {
    version: 2,
    address: recovery.server.address,
    sshPort: recovery.server.sshPort,
    fingerprint: recovery.fingerprint,
    keyType: "ecdsa-sha2-nistp256",
  };
}

// A single unprivileged hosted pilot process owns this directory. Every write
// completes synchronously before a request can observe or use the new state.
export function createHostedUbuntu(directory, enrollment) {
  const initial = readServerRecord(enrollment);
  if (
    !isAbsolute(directory) ||
    initial?.version !== 1 ||
    initial.sshPort !== 22
  )
    throw new Error("Invalid hosted recovery configuration");
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.uid !== owner || info.mode & 0o077)
    throw new Error("Hosted recovery needs a private state directory");
  const path = join(directory, "ubuntu-recovery.json");

  function load() {
    let fd;
    try {
      fd = openSync(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
    } catch (error) {
      if (error.code === "ENOENT")
        return { current: initial, pending: null, last: null };
      throw error;
    }
    try {
      const stat = fstatSync(fd);
      if (
        !stat.isFile() ||
        stat.uid !== owner ||
        stat.nlink !== 1 ||
        stat.mode & 0o077 ||
        stat.size > 4096
      )
        throw new Error("Invalid hosted recovery state file");
      const data = JSON.parse(readFileSync(fd, "utf8"));
      const current = readServerRecord(data.current);
      const pending =
        data.pending === null ? null : readUbuntuRecovery(data.pending);
      const lastJob = data.last ? readUbuntuRecovery(data.last.job) : null;
      const last = lastJob && { job: lastJob, state: data.last.state };
      if (
        data.version !== 1 ||
        data.initial !== initial.fingerprint ||
        !current ||
        current.address !== initial.address ||
        current.sshPort !== 22 ||
        (current.version === 1 && !same(current, initial)) ||
        (data.pending !== null &&
          (!pending || !same(pending.server, current))) ||
        (data.last !== null &&
          (!last ||
            !["complete", ...terminalOriginal].includes(last.state) ||
            !same(
              last.state === "complete"
                ? replacementServer(last.job)
                : last.job.server,
              current,
            )))
      )
        throw new Error("Hosted recovery state does not match enrollment");
      return { current, pending, last };
    } finally {
      closeSync(fd);
    }
  }

  function save(state) {
    const temporary = join(directory, `.${randomUUID()}.tmp`);
    try {
      const fd = openSync(temporary, "wx", 0o600);
      try {
        writeFileSync(
          fd,
          JSON.stringify({
            version: 1,
            initial: initial.fingerprint,
            ...state,
          }) + "\n",
        );
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(temporary, path);
      const parent = openSync(
        directory,
        constants.O_RDONLY | constants.O_DIRECTORY,
      );
      try {
        fsyncSync(parent);
      } finally {
        closeSync(parent);
      }
    } finally {
      try {
        unlinkSync(temporary);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
  }

  load();
  return {
    load,
    begin(candidate) {
      const pending = readUbuntuRecovery(candidate);
      const state = load();
      if (state.pending || !pending || !same(pending.server, state.current))
        throw new Error(
          "Hosted recovery is already open or the server changed",
        );
      save({ ...state, pending });
    },
    finish(job, report) {
      const state = load();
      if (!matchesUbuntuJob(state.pending, job))
        throw new Error("Hosted recovery job changed");
      const complete = report.state === "complete";
      if (
        !complete &&
        !(report.original === true && terminalOriginal.includes(report.state))
      )
        return false;
      save({
        current: complete ? replacementServer(state.pending) : state.current,
        pending: null,
        last: { job: state.pending, state: report.state },
      });
      return true;
    },
  };
}
