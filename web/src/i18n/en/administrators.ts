export const scopedAdministratorStatus = {
  title: "Administrator access",
  check: "Check administrator access",
  states: {
    enabled: "Administrator sharing is configured for this VPN.",
    notEnabled: "Administrator sharing has not been enabled on this server.",
    disabled: "Administrator sharing is disabled on this server.",
    notRegistered:
      "This VPN has no registration in the server’s administrator inventory.",
    unavailable:
      "Rookstride could not verify administrator access for this VPN.",
  },
  roles: {
    infrastructure: "Infrastructure administrator",
    user_manager: "VPN user manager",
    viewer: "Viewer",
  },
  devices: "Registered devices",
  invitations: "Open invitations",
};
