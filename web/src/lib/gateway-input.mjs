// Match server/rookstride/admin.py and passwords.py for new IKEv2 accounts.
export function validLogin(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 64 &&
    !/[^A-Za-z0-9_.@-]/.test(value)
  );
}
export function validVpnPassword(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 127 &&
    new TextEncoder().encode(value).length <= 127 &&
    !/[\u0000-\u001f\u007f-\u009f\u2028\u2029\ud800-\udfff]/u.test(value)
  );
}

export const filterPresets = ["standard", "strong", "strict"];

// Method IDs and client formats match the Android single-server recipes.
export const singleProtocolCatalog = {
  awg: { name: "AmneziaWG 3.1", transport: "udp", extension: "conf" },
  xray: { name: "VLESS · REALITY (TCP)", transport: "tcp", extension: "txt" },
  openvpn: { name: "OpenVPN", transport: "tcp", extension: "ovpn" },
  xhttp: {
    name: "VLESS · XHTTP / REALITY",
    transport: "tcp",
    extension: "txt",
  },
  hysteria2: { name: "Hysteria 2", transport: "udp", extension: "rookvpn" },
  outline: {
    name: "Outline · Shadowsocks / WSS",
    transport: "tcp",
    extension: "rookvpn",
  },
  shadowsocks: {
    name: "Shadowsocks · v2ray-plugin / WSS",
    transport: "tcp",
    extension: "rookvpn",
  },
  trusttunnel: {
    name: "TrustTunnel · HTTP/2",
    transport: "tcp",
    extension: "rookvpn",
  },
  naive: {
    name: "NaïveProxy · HTTP/2",
    transport: "tcp",
    extension: "rookvpn",
  },
};

export const pairExitPorts = Object.freeze({
  awg: 443, openvpn: 1194, ikev2: 500, xray: 443, xhttp: 443,
  hysteria2: 443, outline: 443, shadowsocks: 443, trusttunnel: 443, naive: 443,
});
export const pairEntryPorts = Object.freeze({ ...pairExitPorts, awg: 51820 });
export const hostedPairExits = Object.freeze(["openvpn", "ikev2", "xray"]);
export const mixedPairExits = Object.freeze(Object.keys(pairExitPorts).filter((method) => method !== "awg"));
export const mixedPairEntries = mixedPairExits;

/** @param {unknown} method @returns {method is Exclude<keyof typeof pairExitPorts, "awg">} */
export function isMixedPairExit(method) {
  return typeof method === "string" && mixedPairExits.includes(method);
}

export const isMixedPairEntry = isMixedPairExit;

/** @param {keyof typeof pairEntryPorts} [method] */
export function pairProfileExtension(method = "awg") {
  return method === "ikev2" ? "sswan" : singleProtocolCatalog[method]?.extension;
}

export function readServerRecord(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !(
      (value.version === 1 && Object.keys(value).length === 4) ||
      (value.version === 2 &&
        value.keyType === "ecdsa-sha2-nistp256" &&
        Object.keys(value).length === 5)
    ) ||
    typeof value.address !== "string" ||
    !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(
      value.address,
    ) ||
    value.address.split(".").some((octet) => Number(octet) > 255) ||
    !Number.isInteger(value.sshPort) ||
    value.sshPort < 1 ||
    value.sshPort > 65535 ||
    typeof value.fingerprint !== "string" ||
    !/^SHA256:[A-Za-z0-9+/]{43}$/.test(value.fingerprint)
  )
    return null;
  const { version, address, sshPort, fingerprint, keyType } = value;
  return { version, address, sshPort, fingerprint, ...(version === 2 && { keyType }) };
}

export const ubuntuVersions = ["22.04", "24.04", "26.04"];
export const ubuntuEraseConfirmation = "WIPE SERVER AND REINSTALL UBUNTU";

export function readUbuntuRecovery(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 4 ||
    typeof value.job !== "string" ||
    !/^[a-f0-9]{32}$/.test(value.job) ||
    !ubuntuVersions.includes(value.ubuntu) ||
    typeof value.fingerprint !== "string" ||
    !/^SHA256:[A-Za-z0-9+/]{43}$/.test(value.fingerprint)
  )
    return null;
  const server = readServerRecord(value.server);
  if (!server || server.fingerprint === value.fingerprint) return null;
  return { job: value.job, ubuntu: value.ubuntu, fingerprint: value.fingerprint, server };
}
