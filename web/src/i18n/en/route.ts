export const route = {
  diagram: {
    title: {
      single: "How a one-server VPN connects",
      two: "How a two-server VPN connects",
    },
    vpnKey: "Via your VPN",
    directKey: "Direct connection",
    device: "Your device",
    provider: "Direct route",
    providerAction: "may be blocked",
    entry: "Entry VPS",
    domestic: "In your country",
    server: "Your rented server",
    gateway: "Runs your VPN",
    exit: "Exit VPS",
    abroad: "In another country",
    internet: "Open internet",
    order: "VPN route in order",
    deviceDescription: "Your device.",
    twoEntry: "A rented server in your country receives your connection.",
    singleEntry: "Your rented server runs your VPN.",
    twoExit:
      "The entry server forwards your traffic to a rented server in another country.",
    destination: "Your gateway sends your traffic on to its destination.",
    explore: "Select a point on the map to explore it.",
    close: "Close",
    devices: { phone: "Phone", laptop: "Laptop", desktop: "Desktop" },
    deviceChoice: "Show a device on the map",
    activities: {
      message: "Send a message",
      call: "Make a call",
      book: "Read the news",
    },
    details: {
      device:
        "Your connection starts here. You can use a phone, laptop or desktop with a compatible VPN client.",
      filter:
        "A network may limit access to a destination. The dotted line shows where the direct request was headed. The red line shows the route through your VPN.",
      single:
        "This is the server you rent. Your VPN tunnel ends here. For a website connection, HTTPS keeps traffic encrypted from your device to the site.",
      entry:
        "Your device connects to this server first. It forwards the connection to your exit server. In this illustration, you rent the entry server in your own country.",
      exit: "Your VPN route ends at this second server. The sites you visit see its address. HTTPS keeps a website connection encrypted from your device to the site.",
      internet:
        "From your VPN gateway, you can reach people, information and services online. What you can reach depends on the service and the networks along the way.",
    },
  },
  guide: {
    title: "Rook’s guide to your connection",
    pickRoute: "Choose your route",
    modes: { single: "One rented server", two: "Two rented servers" },
    intro: {
      single: "Your device connects to the internet through a server you rent.",
      two: "Here, a server in your country passes your connection to a second server abroad.",
    },
    setup: {
      title: "Set up your VPN with Rook",
      rent: {
        title: "Choose where to rent",
        body: "Pick a provider and rent a fresh Ubuntu server in the location you want.",
      },
      details: {
        title: "Find your server details",
        body: "Get the server address from your provider. Rook helps you check its identity before you sign in.",
      },
      connect: {
        title: "Connect your first device",
        body: "Review the changes Rook proposes, approve the VPN setup, then connect from your phone or computer.",
      },
      invite: {
        title: "Invite someone",
        body: "Give a friend their own VPN login. You can remove their access later.",
      },
    },
  },
};
