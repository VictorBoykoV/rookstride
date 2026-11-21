type GuideLink = { label: string; href: string };

type Method = {
  title: string;
  input: string;
  steps: string[];
  links: GuideLink[];
};

type Device = {
  id: string;
  title: string;
  icon: "phone" | "laptop" | "desktop";
  methods: Method[];
};

const strongSwanDocs = {
  label: "strongSwan profile help",
  href: "https://docs.strongswan.org/docs/latest/os/androidVpnClientProfiles.html",
};
const amneziaDocs = {
  label: "AmneziaWG illustrated instructions",
  href: "https://docs.amnezia.org/documentation/instructions/use-amneziawg-app/",
};
const openVpnDocs = {
  label: "OpenVPN profile instructions",
  href: "https://openvpn.net/connect-docs/import-profile/",
};

const ikeCredentials = "VPN server address, VPN username and password";
const awgProfile = "AmneziaWG 3.1 .conf file";
const ovpnProfile = "OpenVPN .ovpn file";
const vlessProfile = "vless:// link, sometimes exported in a .txt file";

const awgApple = {
  label: "AmneziaWG on the App Store",
  href: "https://apps.apple.com/app/amneziawg/id6478942365",
};

function vlessMethods(options: Omit<Method, "title">): Method[] {
  const [importStep, ...otherSteps] = options.steps;
  return [
    {
      ...options,
      title: "VLESS TCP/REALITY",
      steps: [
        importStep,
        "Check that the imported connection shows TCP, REALITY and Vision. Select it and connect.",
        ...otherSteps,
      ],
    },
    {
      ...options,
      title: "VLESS XHTTP/REALITY",
      steps: [
        importStep,
        "Check that the imported connection shows XHTTP and REALITY. Select it and connect.",
        ...otherSteps,
      ],
    },
  ];
}

const vlessDesktop = vlessMethods({
  input: vlessProfile,
  steps: [
    "Install v2rayN with Xray. Copy the entire vless:// link, then use the Servers menu to import a share link from the clipboard.",
    "For device-wide routing, enable TUN mode and approve any system prompt. System proxy mode covers apps that use the system proxy.",
  ],
  links: [
    {
      label: "v2rayN releases",
      href: "https://github.com/2dust/v2rayN/releases/latest",
    },
    {
      label: "Find the installer for your computer",
      href: "https://github.com/2dust/v2rayN/wiki/Release-files-introduction",
    },
  ],
});

const devices: Device[] = [
  {
    id: "android",
    title: "Android",
    icon: "phone",
    methods: [
      {
        title: "IKEv2",
        input: "An installed Rookstride VPN or a strongSwan .sswan file",
        steps: [
          "If you set up the gateway in Rookstride, open that VPN in the app and tap Connect.",
          "If you received a profile, open strongSwan VPN Client. In its menu, choose Import VPN profile and select the .sswan file. Enter your VPN password if asked, save, then tap the profile to connect.",
        ],
        links: [
          {
            label: "strongSwan on Google Play",
            href: "https://play.google.com/store/apps/details?id=org.strongswan.android",
          },
          strongSwanDocs,
        ],
      },
      {
        title: "AmneziaWG 3.1",
        input: awgProfile,
        steps: [
          "Install AmneziaWG with 3.1 support. In AmneziaWG, tap + and choose Import from file or archive.",
          "Select your .conf file, then turn on the tunnel and approve the Android VPN prompt.",
        ],
        links: [
          {
            label: "AmneziaWG on Google Play",
            href: "https://play.google.com/store/apps/details?id=org.amnezia.awg",
          },
          amneziaDocs,
        ],
      },
      {
        title: "OpenVPN",
        input: ovpnProfile,
        steps: [
          "Install OpenVPN Connect. Open My Profiles, tap +, then use the file import to select your .ovpn file.",
          "If the profile asks for credentials, enter your VPN username and password. Turn on the profile to connect.",
        ],
        links: [
          {
            label: "OpenVPN Connect on Google Play",
            href: "https://play.google.com/store/apps/details?id=net.openvpn.openvpn",
          },
          openVpnDocs,
        ],
      },
      ...vlessMethods({
        input: vlessProfile,
        steps: [
          "Install v2rayNG with the Xray core. Copy the full link, then tap + and import the configuration from the clipboard.",
        ],
        links: [
          {
            label: "v2rayNG releases",
            href: "https://github.com/2dust/v2rayNG/releases/latest",
          },
        ],
      }),
    ],
  },
  {
    id: "iphone",
    title: "iPhone",
    icon: "phone",
    methods: [
      {
        title: "IKEv2 in iPhone Settings",
        input: ikeCredentials,
        steps: [
          "Go to Settings → General → VPN & Device Management → VPN → Add VPN Configuration. Set Type to IKEv2.",
          "Enter a description and the server address. Set Remote ID to the server identity supplied by your VPN administrator. Choose Username for user authentication, enter your VPN credentials, then tap Done and turn on the VPN.",
        ],
        links: [
          {
            label: "Certificate requirements for iPhone and Mac",
            href: "https://docs.strongswan.org/docs/latest/interop/ios.html",
          },
        ],
      },
      {
        title: "AmneziaWG 3.1",
        input: awgProfile,
        steps: [
          "Save the .conf file in Files. Open AmneziaWG with 3.1 support, tap Add a tunnel, then Create from file or archive.",
          "Select the file, allow the iPhone to add the VPN configuration, then turn on the tunnel.",
        ],
        links: [awgApple, amneziaDocs],
      },
      {
        title: "OpenVPN",
        input: ovpnProfile,
        steps: [
          "Save the file in Files. Install OpenVPN Connect, then open My Profiles, tap + and select the .ovpn file.",
          "Confirm the import, allow the VPN configuration and connect. Enter your VPN credentials if prompted.",
        ],
        links: [
          {
            label: "OpenVPN Connect on the App Store",
            href: "https://apps.apple.com/us/app/openvpn-connect/id590379981",
          },
          openVpnDocs,
        ],
      },
      ...vlessMethods({
        input: vlessProfile,
        steps: [
          "Install V2Box. Copy the complete link. In Configs, use + to import from the clipboard.",
        ],
        links: [
          {
            label: "V2Box on the App Store",
            href: "https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690",
          },
        ],
      }),
    ],
  },
  {
    id: "macos",
    title: "macOS",
    icon: "laptop",
    methods: [
      {
        title: "IKEv2 in System Settings",
        input: ikeCredentials,
        steps: [
          "Open System Settings → Network. Open the action menu, choose Add VPN Configuration → IKEv2 and give the service a name.",
          "Enter the server address and its Remote ID. For Authentication, choose Username and enter the VPN username and password. Create the service, then turn it on in System Settings → VPN.",
        ],
        links: [
          {
            label: "Apple Mac VPN settings guide",
            href: "https://support.apple.com/en-lb/guide/mac-help/mchlp2963/mac",
          },
          {
            label: "Certificate requirements for iPhone and Mac",
            href: "https://docs.strongswan.org/docs/latest/interop/ios.html",
          },
        ],
      },
      {
        title: "AmneziaWG 3.1",
        input: awgProfile,
        steps: [
          "Open AmneziaWG with 3.1 support and choose Import tunnel(s) from file. Select your .conf file.",
          "Select the imported tunnel and activate it. Approve the macOS VPN prompt if it appears.",
        ],
        links: [awgApple, amneziaDocs],
      },
      {
        title: "OpenVPN",
        input: ovpnProfile,
        steps: [
          "Install OpenVPN Connect. Drag the .ovpn file into the app and confirm the import.",
          "Turn on the imported profile. Enter your VPN credentials if prompted.",
        ],
        links: [
          {
            label: "OpenVPN Connect for macOS",
            href: "https://openvpn.net/connect-docs/connect-for-macos/",
          },
          openVpnDocs,
        ],
      },
      ...vlessDesktop,
    ],
  },
  {
    id: "windows",
    title: "Windows",
    icon: "desktop",
    methods: [
      {
        title: "IKEv2 in Windows Settings",
        input: ikeCredentials,
        steps: [
          "Open Settings → Network & internet → VPN → Add VPN. Select Windows (built-in) and name the connection.",
          "Enter the server name covered by the certificate, choose IKEv2 and User name and password, then save. Select the new profile and choose Connect.",
        ],
        links: [
          {
            label: "Microsoft VPN settings guide",
            href: "https://support.microsoft.com/en-us/windows/experience/connectivity-networking/connect-to-a-vpn-in-windows",
          },
          {
            label: "strongSwan IKEv2 steps with screenshots",
            href: "https://docs.strongswan.org/docs/latest/interop/windowsEapConf.html",
          },
        ],
      },
      {
        title: "AmneziaWG 3.1",
        input: awgProfile,
        steps: [
          "Install AmneziaWG with 3.1 support. Click Add Tunnel and open the .conf file.",
          "Select the imported tunnel and click Activate.",
        ],
        links: [
          {
            label: "AmneziaWG Windows releases",
            href: "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest",
          },
          amneziaDocs,
        ],
      },
      {
        title: "OpenVPN",
        input: ovpnProfile,
        steps: [
          "Install OpenVPN Connect. Drag the .ovpn file into the app or use its file import, then confirm.",
          "Turn on the imported profile. Enter your VPN credentials if prompted.",
        ],
        links: [
          {
            label: "OpenVPN Connect for Windows",
            href: "https://openvpn.net/client/",
          },
          openVpnDocs,
        ],
      },
      ...vlessDesktop,
    ],
  },
];

const rookVpnMethods = [
  "Hysteria 2",
  "Outline / Shadowsocks over TLS WebSockets",
  "Shadowsocks / v2ray-plugin over TLS WebSockets",
  "TrustTunnel",
  "NaïveProxy",
];

function rookVpnMethod(title: string, android: boolean): Method {
  return {
    title,
    input: "Rookstride .rookvpn file",
    steps: android
      ? [
          "In a Rookstride Android build with the expanded method catalog, open Connect to a VPN and choose Import a connection file.",
          "Select this method, open the .rookvpn file, then tap Connect.",
        ]
      : [
          "Rookstride's export for this method includes its VPN credentials and server trust. The documented import uses a compatible Rookstride Android build.",
          "Ask your VPN administrator for a device-specific profile, or use an Android device with the expanded build.",
        ],
    links: android
      ? []
      : [
          {
            label: "Android instructions",
            href: "/connect?device=android#methods",
          },
        ],
  };
}

export const connectionGuide = {
  title: "Connect your device to your VPN",
  metaTitle: "VPN connection guide for Android, iPhone, Mac and Windows",
  lead: "Already have a VPN? Choose your device, then follow the steps for the profile or sign-in details you received.",
  deviceNav: "Choose your device",
  navLabel: "Connect a device",
  androidTitle: "Rookstride for Android",
  getAndroid: "Get Rookstride for Android",
  androidSummary:
    "The Rookstride Android prerelease can set up a server and connect using any of the ten methods listed here. You can also import an exported profile into a compatible client below.",
  beforehand: "Before you connect",
  profileHelp:
    "Ask the VPN owner for a connection file, a connection link, or VPN sign-in details for your device. If you own the gateway, export a profile from its VPN account. Keep the file or link private because it can grant VPN access.",
  setupLink: "Set up a VPN first",
  ikeTrust:
    "For built-in IKEv2, use a server identity covered by a certificate your device trusts. If your VPN owner uses private trust, ask them for the verified CA certificate and installation instructions for your device. Import a .sswan file in strongSwan on Android. For Apple and Windows Settings, follow the manual steps for your device below.",
  awgVersion:
    "Use the 3.1 client for an AmneziaWG 3.1 export. Ordinary WireGuard and older AmneziaWG versions use different profiles.",
  methodTitle: "Connection methods",
  checkTitle: "Check your connection",
  checkBody:
    "After connecting, open an HTTPS site and check that your public IP matches your VPN’s expected exit. For Double VPN, connect with the entry server’s profile and expect the exit server’s address. This check tells you where the browser reaches the internet from.",
  devices: devices.map((device) => ({
    ...device,
    methods: [
      ...device.methods,
      ...rookVpnMethods.map((title) =>
        rookVpnMethod(title, device.id === "android"),
      ),
    ],
  })),
};
