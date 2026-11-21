import { previewMessages } from "../i18n/en/management-status.mjs";

export const previewAddress = "192.0.2.10";
const scenarios = new Set(["fresh", "existing", "unreachable", "changed-key"]);

export function inspectExample(input) {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some((key) => !["address", "scenario"].includes(key)) ||
    input.address !== previewAddress ||
    !scenarios.has(input.scenario)
  ) {
    throw new Error(previewMessages.invalidExample);
  }
  const base = {
    mode: "fixture",
    serverContacted: false,
    address: previewAddress,
    scenario: input.scenario,
    protocol: "AmneziaWG",
    executionAvailable: false,
  };
  if (input.scenario === "unreachable")
    return {
      ...base,
      state: "unreachable",
      title: previewMessages.unreachableTitle,
      detail: previewMessages.unreachableDetail,
      steps: [],
    };
  if (input.scenario === "changed-key")
    return {
      ...base,
      state: "blocked",
      title: previewMessages.identityTitle,
      detail: previewMessages.identityDetail,
      steps: [],
    };
  if (input.scenario === "existing")
    return {
      ...base,
      state: "review",
      title: previewMessages.existingTitle,
      detail: previewMessages.existingDetail,
      steps: [],
    };
  return {
    ...base,
    state: "example-ready",
    title: previewMessages.freshTitle,
    detail: previewMessages.freshDetail,
    steps: [
      previewMessages.confirmIdentity,
      previewMessages.checkSystem,
      previewMessages.prepareVpn,
      previewMessages.applySetup,
      previewMessages.verifyServer,
    ],
  };
}
