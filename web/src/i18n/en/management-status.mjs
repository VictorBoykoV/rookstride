// English fallback for existing API and MCP callers. The UI resolves stable keys in its own locale.
export const gatewayMessages = {
  ready: "Your server passed the pre-installation checks.",
  occupied:
    "This server has existing software, listeners or an unfinished setup. Use a fresh server for this installation.",
  unsupported:
    "This setup needs a dedicated Ubuntu 22.04, 24.04 or 26.04 LTS server with root access on a supported processor.",
  running:
    "The server is installing the VPN and checking its private DNS and ad filtering. This can take several minutes.",
  installed:
    "The server completed its setup and verification. Connect a device to test your own route.",
  removing:
    "The server is stopping the VPN and removing its owned files and firewall rules.",
  removed:
    "The browser-managed VPN was removed. Ubuntu and SSH are still available.",
  protocolRunning:
    "The server is installing the VPN protocol and checking its services.",
  protocolInstalled: "The installation passed the server checks.",
  protocolFailed:
    "Protocol setup stopped before verification. Inspect the server before trying again.",
  failed:
    "The installation or its checks did not finish successfully. Inspect the server before another attempt.",
  indeterminate:
    "Contact with the server was interrupted. Inspect it again to find out what completed.",
  installationFailed:
    "Setup stopped while installing packages or configuring the VPN. Check the server and its Ubuntu package sources before attempting recovery.",
  verificationFailed:
    "Installation finished, but the server did not pass the VPN, DNS and ad-filter checks. Inspect the existing setup before using or reinstalling it.",
  localUserRequired:
    "Start the personal browser app as a regular user on this computer.",
  invalidProfile: "The server did not return a usable profile.",
  invalidCertificate: "The server did not return a valid gateway CA.",
  sessionEnded: "This setup session has ended. Check your server again.",
  invalidServerDetails:
    "Enter a public IPv4 address, SSH port, host fingerprint and root password.",
  sessionAlreadyOpen:
    "This tab already has a setup session. Close it or open a new setup tab.",
  targetInUse:
    "A setup session already holds this server address. Close that session or wait for it to expire.",
  sessionLimitReached:
    "Both setup sessions are in use. Close one or wait for it to expire.",
  tooManyAttempts: "Too many connection attempts. Try again in a minute.",
  identityMismatch:
    "The server’s SSH identity differs from the supplied fingerprint. Its password was withheld.",
  inspectionUnavailable:
    "Could not inspect this server. Check its address, SSH fingerprint, port and root sign-in.",
  invalidInstallDetails: "Review the username, VPN password and confirmation.",
  operationBusy: "Wait for the current operation to finish.",
  verifiedSessionRequired:
    "A verified gateway and an idle session are required.",
  invalidGuestDetails:
    "Check the account details and review the current guest list.",
  invalidMaintenanceDetails:
    "Review the requested server settings before applying them.",
  invalidUbuntuReinstall: "Review the Ubuntu version, recovery details and erase confirmation.",
  ubuntuReviewUnavailable:
    "The server could not prepare a reinstall review. Check the disk, boot layout and any active maintenance in your provider console.",
  ubuntuReviewExpired:
    "Review the Ubuntu reinstall again. The previous review expired or the server changed.",
  ubuntuReinstalling:
    "The approved Ubuntu reinstall may be running. Check the recorded job before making another change.",
  ubuntuStatusUnavailable: "The Ubuntu job could not be checked. Try checking the same recovery record.",
  ubuntuRecoveryChanged:
    "The saved Ubuntu job does not match the hosted server. Reopen the workspace to check its current state.",
  removalReviewRequired:
    "Review the VPN removal again. The previous review may have expired or changed.",
  protocolReviewRequired:
    "Review the VPN protocol, port and owner again before starting setup.",
  protocolRuntimeUnavailable:
    "The verified Rookstride runtime is unavailable for this server. Ask the web app operator or choose another method.",
  maintenanceResultUnknown:
    "The server could not confirm these settings. Check the server before retrying.",
  pairRequiresTwoServers:
    "Double VPN needs two different servers. Both addresses identified the same server.",
  pairInspectionBusy:
    "Close active single-server setup sessions and wait for any running check before inspecting a pair.",
  pairEntryDnsConflict:
    "The entry server has existing private DNS state. Use a clean entry server or review the existing VPN and DNS setup before trying again.",
  pairRecoveryUnavailable:
    "The owner recovery file could not be verified for this Double VPN. Check the file, passphrase and both server identities.",
  rosterChanged:
    "The guest list or gateway changed. Refresh and review before trying again.",
  invalidRoster:
    "The access list could not be verified. Refresh it before making another change.",
  guestResultUnknown:
    "The server could not confirm the result. Refresh the guest list or inspect the server again.",
  unknownAction: "Unknown setup action.",
  localOriginRequired: "Open the local browser app on this computer.",
  jsonRequired: "Send a JSON setup request.",
  requestRequired: "A setup request is required.",
  requestTooLarge: "The setup request is too large.",
  unreadableRequest: "The setup request could not be read.",
  serviceUnavailable: "The VPN setup service is unavailable.",
};

export const previewMessages = {
  invalidExample:
    "This preview accepts only its example address and listed scenarios. Do not enter credentials.",
  unreachableTitle: "Example: the server did not answer",
  unreachableDetail:
    "A real check would stop here and offer a safe retry. No deployment would start.",
  identityTitle: "Example: the server identity changed",
  identityDetail:
    "Stop before sending credentials. The saved identity must be reviewed before proceeding.",
  existingTitle: "Example: existing software found",
  existingDetail:
    "An occupied server needs inspection and an explicit plan. Setup must not overwrite it.",
  freshTitle: "Example: a fresh Ubuntu server",
  freshDetail:
    "This sample shows the proposed stages. Nothing has been inspected or installed.",
  confirmIdentity: "Confirm the server identity",
  checkSystem: "Check the supported system and existing software",
  prepareVpn: "Prepare the VPN configuration",
  applySetup: "Apply the reviewed setup",
  verifyServer: "Verify the server and export client access",
  localOnly: "Use the local preview page.",
  jsonRequired: "Expected a preview JSON request.",
  tooLarge: "Preview request is too large.",
  invalidRequest:
    "Only the listed example server/scenarios are accepted. Do not submit credentials.",
};
