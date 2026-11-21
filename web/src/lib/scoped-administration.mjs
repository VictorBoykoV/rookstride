const roles = /** @type {const} */ ([
  "infrastructure",
  "user_manager",
  "viewer",
]);
const states = /** @type {const} */ ([
  "notEnabled",
  "disabled",
  "notRegistered",
  "unavailable",
]);

/** @typedef {(typeof roles)[number]} AdministrationRole */
/** @typedef {{role: AdministrationRole, devices: number, invitations: number}} RoleCount */
/** @typedef {{state: "enabled", roles: RoleCount[]} | {state: (typeof states)[number]}} AdministrationStatus */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function record(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

/** @param {unknown} value @returns {value is number} */
function count(value) {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= 4096
  );
}

/** @param {unknown} result @returns {AdministrationStatus} */
export function cleanScopedAdministration(result) {
  if (!record(result)) return { state: "unavailable" };
  const state = states.find((state) => state === result.state);
  if (state && Object.keys(result).length === 1) return { state };
  if (
    result.state !== "enabled" ||
    Object.keys(result).length !== 2 ||
    !Array.isArray(result.roles) ||
    result.roles.length !== roles.length
  ) {
    return { state: "unavailable" };
  }
  const counts = [];
  for (const [index, role] of roles.entries()) {
    const value = result.roles[index];
    if (
      !record(value) ||
      Object.keys(value).length !== 3 ||
      value.role !== role ||
      !count(value.devices) ||
      !count(value.invitations)
    ) {
      return { state: "unavailable" };
    }
    counts.push({
      role,
      devices: value.devices,
      invitations: value.invitations,
    });
  }
  return { state: "enabled", roles: counts };
}
