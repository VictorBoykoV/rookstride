import {
  createCipheriv,
  createDecipheriv,
  pbkdf2,
  randomBytes,
} from "node:crypto";
import { isIPv4 } from "node:net";
import { promisify } from "node:util";
import { isMixedPairExit, pairExitPorts } from "./gateway-input.mjs";

export const maxPairRecoveryBytes = 2 * 1024 * 1024;

const magic = Buffer.from("ROOKREC1", "ascii");
const iterations = 250_000;
const saltOffset = 12;
const nonceOffset = 28;
const headerSize = 40;
const tagSize = 16;
const deriveKey = promisify(pbkdf2);
const roles = ["entry", "exit"];

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateArchive(archive, review) {
  const deployment = review?.pairId;
  const entry = review?.entry?.address;
  const exit = review?.exit?.address;
  const exitProtocol = review?.exitProtocol ?? "awg";
  if (
    (review?.exitProtocol !== undefined && !isMixedPairExit(review.exitProtocol)) ||
    typeof deployment !== "string" ||
    !/^[a-f0-9]{32}$/.test(deployment) ||
    !isIPv4(entry) ||
    !isIPv4(exit) ||
    entry === exit ||
    !record(archive) ||
    archive.schema !== 1 ||
    archive.purpose !== "rookstride-owner-recovery" ||
    archive.deployment !== deployment ||
    !record(archive.nodes) ||
    Object.keys(archive.nodes).length !== roles.length
  )
    throw new Error("Recovery archive does not match the reviewed Double VPN.");

  const topology = {
    pair: deployment,
    server: entry,
    exit_host: exit,
    vpn_port: 51820,
    tunnel_port: pairExitPorts[exitProtocol],
    entry_protocol: "awg",
    exit_protocol: exitProtocol,
    engine: "native-v2",
    client_pool: "10.66.0.0/24",
    test_ip: "10.249.255.254",
    entry_address: "10.253.0.2/30",
    exit_address: "10.253.0.1/30",
    route_table: 51831,
  };
  for (const role of roles) {
    const node = archive.nodes[role];
    const initial = node?.initial_user;
    const isEntry = role === "entry";
    const protocol = isEntry ? "awg" : exitProtocol;
    const server = isEntry ? entry : exit;
    const port = isEntry ? topology.vpn_port : topology.tunnel_port;
    if (
      !record(node) ||
      node.purpose !== "rookstride-owner-recovery-node" ||
      node.deployment !== deployment ||
      node.role !== role ||
      !record(node.state) ||
      node.state.protocol !== protocol ||
      ((exitProtocol !== "awg" || Object.hasOwn(node.state, "server")) && node.state.server !== server) ||
      ((exitProtocol !== "awg" || Object.hasOwn(node.state, "port")) && node.state.port !== port) ||
      (node.state.access_mode !== undefined && node.state.access_mode !== "profile") ||
      ![1, 2].includes(node.schema) ||
      (exitProtocol !== "awg" && node.schema !== 2) ||
      (node.schema === 2 && node.adapter !== protocol + "-identity-v1") ||
      !record(initial) ||
      typeof initial.login !== "string" ||
      !/^[A-Za-z0-9_.@-]{1,64}$/.test(initial.login) ||
      initial.login !== node.state.initialLogin ||
      (isEntry && review.login !== undefined && initial.login !== review.login) ||
      typeof initial.password !== "string" ||
      !initial.password ||
      !record(node.plan) ||
      node.plan.role !== role ||
      (node.plan.access_mode !== undefined && node.plan.access_mode !== "") ||
      Object.keys(node.plan).some(
        (name) => name !== "role" && name !== "access_mode" && !Object.hasOwn(topology, name),
      ) ||
      Object.entries(topology).some(
        ([name, value]) => node.plan[name] !== value,
      )
    )
      throw new Error(
        "Recovery archive does not match a reviewed pair member.",
      );
  }
  return archive;
}

async function keyFor(password, salt) {
  if (
    typeof password !== "string" ||
    password.length < 12 ||
    !password.isWellFormed()
  )
    throw new Error("Use a valid recovery password of at least 12 characters.");
  const bytes = Buffer.from(password, "utf8");
  try {
    return await deriveKey(bytes, salt, iterations, 32, "sha256");
  } finally {
    bytes.fill(0);
  }
}

export async function encryptPairRecovery(archive, password, review) {
  const serialized = JSON.stringify(validateArchive(archive, review));
  if (
    Buffer.byteLength(serialized, "utf8") >
    maxPairRecoveryBytes - headerSize - tagSize
  )
    throw new Error("Recovery archive is too large.");

  const header = Buffer.alloc(headerSize);
  magic.copy(header);
  header.writeUInt32BE(iterations, magic.length);
  randomBytes(headerSize - saltOffset).copy(header, saltOffset);
  const plain = Buffer.from(serialized, "utf8");
  let key;
  try {
    key = await keyFor(password, header.subarray(saltOffset, nonceOffset));
    const cipher = createCipheriv(
      "aes-256-gcm",
      key,
      header.subarray(nonceOffset),
      { authTagLength: tagSize },
    );
    cipher.setAAD(header);
    return Buffer.concat([
      header,
      cipher.update(plain),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
  } finally {
    key?.fill(0);
    plain.fill(0);
  }
}

export async function decryptPairRecovery(bytes, password, review) {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength < headerSize + tagSize ||
    bytes.byteLength > maxPairRecoveryBytes
  )
    throw new Error("Unsupported owner recovery file.");
  const envelope = Buffer.from(bytes);
  const header = envelope.subarray(0, headerSize);
  if (
    !header.subarray(0, magic.length).equals(magic) ||
    header.readUInt32BE(magic.length) !== iterations
  )
    throw new Error("Unsupported owner recovery file.");

  const key = await keyFor(password, header.subarray(saltOffset, nonceOffset));
  let first;
  let last;
  let plain;
  let archive;
  try {
    const cipherEnd = envelope.length - tagSize;
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      header.subarray(nonceOffset),
      { authTagLength: tagSize },
    );
    decipher.setAAD(header);
    decipher.setAuthTag(envelope.subarray(cipherEnd));
    first = decipher.update(envelope.subarray(headerSize, cipherEnd));
    last = decipher.final();
    plain = last.length ? Buffer.concat([first, last]) : first;
    archive = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(plain),
    );
  } catch {
    throw new Error(
      "Could not authenticate or decode the owner recovery file.",
    );
  } finally {
    key.fill(0);
    first?.fill(0);
    last?.fill(0);
    if (plain !== first) plain?.fill(0);
  }
  return validateArchive(archive, review);
}
