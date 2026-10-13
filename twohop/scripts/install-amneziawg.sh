#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-1200}"
[[ "$APT_LOCK_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || {
  echo "APT_LOCK_TIMEOUT_SECONDS must be a non-negative integer." >&2
  exit 1
}

apt_get() {
  apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_TIMEOUT_SECONDS" "$@"
}

ROLE="${1:-}"
if [[ "$ROLE" != "ingress" && "$ROLE" != "egress" ]]; then
  echo "Usage: $0 ingress|egress" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "This installer must run as root." >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Cannot identify the operating system." >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "debian" ]]; then
  echo "Supported operating systems: Ubuntu and Debian." >&2
  exit 1
fi

echo "Installing AmneziaWG prerequisites for the $ROLE node..."
echo "Package operations will wait up to ${APT_LOCK_TIMEOUT_SECONDS}s for an existing apt/dpkg job."
apt_get update -qq
apt_get install -y -qq \
  ca-certificates \
  curl \
  gnupg2 \
  iproute2 \
  iptables \
  jq \
  python3-launchpadlib \
  software-properties-common

running_kernel="$(uname -r)"
running_headers="linux-headers-$running_kernel"
reboot_needed=false
# Consume the full output: grep -q can SIGPIPE apt-cache under pipefail.
header_candidate="$(apt-cache policy "$running_headers" | awk '/Candidate:/ {print $2}')"
if [[ -d "/lib/modules/$running_kernel/build" || ( -n "$header_candidate" && "$header_candidate" != '(none)' ) ]]; then
  apt_get install -y -qq "$running_headers"
else
  echo "Headers for the running kernel ($running_kernel) are unavailable."
  echo "Installing the distribution's current generic kernel and headers..."
  if [[ "$ID" == "ubuntu" ]]; then
    apt_get install -y -qq --no-install-recommends linux-image-generic linux-headers-generic
  else
    case "$(dpkg --print-architecture)" in
      amd64) kernel_arch=amd64 ;;
      arm64) kernel_arch=arm64 ;;
      *) echo 'Unsupported kernel architecture.' >&2; exit 1 ;;
    esac
    apt_get install -y -qq "linux-image-$kernel_arch" "linux-headers-$kernel_arch"
  fi
  reboot_needed=true
fi

if [[ "$ROLE" == "egress" ]]; then
  apt_get install -y -qq unbound dnsutils
fi

if ! grep -RqsE '^[[:space:]]*deb .*ppa\.launchpadcontent\.net/amnezia/ppa' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  add-apt-repository -y ppa:amnezia/ppa
fi

apt_get update -qq
# Tested tool/module pair. Updating these requires a config round-trip and pair gates.
TOOLS_VERSION="${AWG_TOOLS_VERSION:-1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1}"
MODULE_VERSION="${AWG_MODULE_VERSION:-1.0.0-0~202609061402+4569c4c~ubuntu24.04.1}"
[[ "$TOOLS_VERSION" =~ ^[A-Za-z0-9.+:~_-]+$ && "$MODULE_VERSION" =~ ^[A-Za-z0-9.+:~_-]+$ ]] || { echo 'Invalid package version.' >&2; exit 1; }
if [[ "$ID" == ubuntu && "${VERSION_ID:-}" == 24.04 ]]; then
  apt_get install -y -qq "amneziawg=$TOOLS_VERSION" "amneziawg-dkms=$MODULE_VERSION"
else
  echo 'Package pin defaults are tested on Ubuntu 24.04 only; set matching version overrides for other releases.' >&2
  [[ -n ${AWG_TOOLS_VERSION:-} && -n ${AWG_MODULE_VERSION:-} ]] || exit 1
  apt_get install -y -qq "amneziawg=$TOOLS_VERSION" "amneziawg-dkms=$MODULE_VERSION"
fi

if ! modprobe amneziawg; then
  if [[ "$reboot_needed" == true ]]; then
    echo "REBOOT_REQUIRED: boot the newly installed kernel, then run this installer again."
    exit 194
  fi
  echo "The AmneziaWG module could not be loaded for kernel $running_kernel." >&2
  exit 1
fi
command -v awg >/dev/null
command -v awg-quick >/dev/null
test -d /sys/module/amneziawg

mkdir -p /etc/amnezia/amneziawg
chmod 700 /etc/amnezia /etc/amnezia/amneziawg

echo "Installed: $(awg --version | head -n 1)"
echo "Kernel module: $(modinfo -F version amneziawg 2>/dev/null || echo loaded)"
