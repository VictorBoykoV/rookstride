export const recipePaths = [
  "gateway/scripts/install.sh",
  "gateway/scripts/ubuntu_support.py",
  "gateway/scripts/validate-inputs.py",
  "gateway/scripts/public-artifact-cache.py",
  "gateway/scripts/render-adguard-config.py",
  "gateway/scripts/vpn-firewall",
  "gateway/scripts/verify.sh",
  "gateway/scripts/prepare-adguard.py",
  "gateway/templates/AdGuardHome.yaml",
  "gateway/systemd/adguardhome.service",
  "gateway/systemd/single-vps-vpn-firewall.service",
  "server/ike_packages.py",
  "server/rookstride/passwords.py",
];

export const accountPaths = [
  "server/ike_public.py",
  "server/rookstride/__init__.py",
  "server/rookstride/admin.py",
  "server/rookstride/engine_guard.py",
  "server/rookstride/passwords.py",
  "server/rookstride/usage.py",
  "server/rookstride/vici.py",
];

export const lifecyclePaths = [
  "reinstall/run.py",
  "server/ike_packages.py",
  "server/reset.py",
  "single/access.py",
  "single/model.py",
  "single/user_updates.py",
];

export const reinstallPaths = [
  "reinstall/run.py",
  "reinstall/boot-pins.json",
  "reinstall/upstream.json",
];

export const routeArchitectures = ["x86_64", "aarch64"];

export const singlePaths = [
  "server/ike_packages.py",
  "server/reset.py",
  ...[
    "Dockerfile.awg",
    "Dockerfile.openvpn",
    "access.py",
    "artifact_bridge.py",
    "entry-awg.sh",
    "entry-openvpn.sh",
    "filtering.py",
    "inspect_server.py",
    "install_retry.py",
    "model.py",
    "openvpn-admin.sh",
    "openvpn-password.py",
    "openvpn_metrics.py",
    "pins.json",
    "public-artifacts.json",
    "public_tls.py",
    "reset_server.py",
    "routes-pins.json",
    "routes.py",
    "run.py",
    "runtime.py",
    "ubuntu_support.py",
    "user_updates.py",
    "xray_users.py",
  ].map((name) => "single/" + name),
];
