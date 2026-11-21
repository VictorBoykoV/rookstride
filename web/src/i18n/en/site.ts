import { connectionGuide } from "./connect";

export const site = {
  connect: connectionGuide,
  shell: {
    wordmark: "Rookstride",
    how: "How it works",
    journal: "Journal",
    comics: "Comics",
    providers: "For providers",
    start: "Get started",
    motto: "Your gateway. Keep moving.",
    browser: "Browser workspace",
    android: "Android app",
    agents: "AI-assistant tools",
    partner: "For VPS providers",
    source: "Source code",
    homeLabel: "Rookstride home",
    mainNav: "Main navigation",
    footerNav: "Footer navigation",
  },
  layout: {
    skip: "Skip to content",
    pageTitle: "Rookstride – Build your own VPN",
    description:
      "Rent a server, set up your own VPN and choose who can use it. Explore Rookstride with Rook as your guide.",
  },
  demo: {
    action: "Try the VPN setup demo",
  },
  home: {
    metaTitle: "Rookstride – Build your own VPN",
    metaDescription:
      "Set up a VPN on an Ubuntu server you rent. Explore single-server VPN, two-server Double VPN, and DNS filtering for ads and trackers.",
    headline: "Run a VPN {ownership}",
    accent: "you control.",
    lead: "When a site is blocked on your network, a VPN can give you another way to reach it. Rook helps you set up your own VPN and share it with people you choose.",
    start: "Set up your VPN",
    options: "Choose how to set up your VPN",
    technology: "How Rookstride works",
    cost: "Rookstride is free and open source. You rent your server from a hosting provider and pay them directly.",
    bridgeAlt:
      "Rook and a traveler fasten a plank while a girl checks the bridge plan in her fieldbook. Across the water, a single path leads from the ruined timber crossing to the fairground.",
    meetRook: "Meet Rook",
    ownerTitle: "You’re in charge after setup.",
    ownerLead:
      "On supported gateways, you can look after the connection yourself. The tools available depend on your app and VPN method.",
    accessTitle: "Choose who can connect",
    accessBody:
      "Give a friend or family member their own access. Revoke it later without changing anyone else’s connection.",
    usageTitle: "See how much data you use",
    usageBody:
      "Check estimated traffic on your gateway when you’re deciding whether your server plan still fits.",
    filterTitle: "Filter out ads and trackers",
    filterBody:
      "Adjust AdGuard Home’s DNS filtering to block requests to known advertising and tracking domains.",
    journalTitle: "From the journal",
    articles: "All articles",
  },
  selfHosted: {
    title: "How Rookstride works",
    metaTitle: "VPN technology and routes",
    lead: "Rookstride is free, open-source software for setting up and managing a VPN on Ubuntu servers you rent. You pay your hosting provider for the servers and any bandwidth charges.",
    one: {
      title: "Single VPN on one server",
      body: "One server accepts the VPN connection from your device and sends its traffic to the internet. Websites see that server’s public IP address. On supported setups, AdGuard Home filters DNS on the same server.",
      details: "You rent, update, and troubleshoot one server. That makes Single VPN a straightforward choice for everyday browsing or sharing access. Set it up with the Android app, the Ubuntu scripts, or the invite-only browser pilot on an approved VPS.",
    },
    two: {
      title: "Double VPN on two servers",
      body: "Your device connects to an entry server. An encrypted link carries traffic from the entry to a separate exit server. Websites see the exit’s public IP address. On supported pairs, DNS filtering runs at the exit.",
      details: "Two servers let you choose separate locations for the entry and exit. You manage both servers, and the link between them can add delay. The Android prerelease offers experimental setup for Double VPN. The browser pilot uses approved servers and invitations.",
    },
    comparison: {
      title: "Compare the two routes",
      columns: ["What to compare", "Single VPN", "Double VPN"],
      rows: [
        [
          "Traffic path",
          "Device → VPN server → internet",
          "Device → entry server → exit server → internet",
        ],
        [
          "Public address",
          "Sites see the VPN server’s address.",
          "Sites see the exit server’s address.",
        ],
        [
          "Servers and cost",
          "One VPS and one hosting bill.",
          "Two separate VPSs and two hosting bills.",
        ],
        [
          "DNS filtering",
          "AdGuard Home runs on the VPN server when supported.",
          "AdGuard Home runs on the exit server when supported.",
        ],
        [
          "Speed and delay",
          "One VPN hop. Speed depends on your connection and the VPS.",
          "The extra hop can add latency. Both VPSs and their link affect speed.",
        ],
        [
          "During an outage",
          "The VPN needs one server to stay reachable.",
          "The VPN needs both servers and the link between them.",
        ],
        [
          "Setup",
          "Android, scripts, the invited web app, or the local MCP connector.",
          "Android prerelease, Ubuntu scripts, or the local MCP connector for supported pairs. Hosted browser access is invite-only.",
        ],
        [
          "When to choose it",
          "You want fewer parts to manage and one hosting bill.",
          "You want separate locations for the entry and exit and can maintain both.",
        ],
      ],
    },
    filter: {
      title: "Fewer ads and trackers with DNS filtering",
      body: "Supported setups use AdGuard Home to block lookups for known advertising, tracking, and analytics domains. This can reduce requests to those services. Ads and trackers served from the same domain as the content may still appear.",
    },
    methods: {
      title: "Connection methods",
      body: "These ten methods are available for single-server setup in the browser pilot and local operator connector. Choose a method your device can use, then import its profile with a compatible VPN app.",
    },
    assistants: {
      title: "Explore setup with an AI assistant",
      body: "The public MCP connector demonstrates setup with examples. The local operator connector lets your assistant inspect and manage your pinned VPS with your approval.",
    },
    singleGuide: "Read the single-server setup guide",
    doubleGuide: "Get the two-server Ubuntu scripts",
    androidPairGuide: "Read the Android Double VPN guide",
    agentGuide: "Connect an assistant",
    source: "View the open-source code",
  },
  start: {
    eyebrow: "Get started",
    title: "Where would you like to set up your VPN?",
    lead: "Choose the tool that fits the way you work. You rent the server and keep its administrator sign-in.",
    telegram: "Telegram",
    telegramBody:
      "A Mini App for managing your VPN inside Telegram is planned.",
    planned: "Planned",
    rentalTitle: "Renting your first server?",
    rentalBody:
      "A virtual private server, or VPS, is a computer you rent online. You choose the provider and pay them directly.",
    prerequisite:
      "For browser setup, use a fresh Ubuntu 22.04, 24.04 or 26.04 LTS server with a public IPv4 address.",
    fingerprint:
      "Use the provider’s console to find its SSH fingerprint. Rookstride uses it to check that you’re signing in to the right server.",
    signIn:
      "Have the administrator sign-in ready. Check the release notes if you’re using the Android app.",
    seeRoute: "See how the connection works",
    metaTitle: "Choose how to start",
    browser: {
      name: "Web browser",
      description:
        "Run Rookstride on your computer to set up one fresh Ubuntu server. You can also practice managing access before you rent one.",
      action: "Open the browser app",
    },
    browserPractice: {
      name: "Web browser",
      description:
        "Try setup and guest access with a sample server. Hosted VPN setup is still in development.",
      action: "Open the VPN setup demo",
    },
    browserHosted: {
      name: "Web browser",
      description:
        "Set up and manage your VPN on this website with an invitation to the browser pilot.",
      action: "Open the web app",
    },
    android: {
      name: "Android phone",
      description:
        "Install the app to set up a supported gateway, connect your phone and manage who can use the VPN.",
      action: "Get the Android app",
    },
    assistant: {
      name: "AI assistant",
      description:
        "Connect Codex, Claude Code, Cursor or Gemini CLI to the practice tools and explore setup with a sample server.",
      action: "Connect an assistant",
    },
  },
  missing: {
    eyebrow: "A TURN WE HAVEN’T TAKEN",
    title: "This page isn’t here.",
    description: "The page may be unpublished or the address may have changed.",
    home: "Back to the start →",
  },
  download: {
    platform: "Android",
    title: "Manage your VPN from your phone.",
    lead: "Install Rookstride to set up a supported gateway and share VPN access with family and friends. Each release lists the servers and connection methods it supports.",
    apkTitle: "Get the Android app",
    apkBody:
      "The 0.4.0-alpha6 prerelease supports ten connection methods and experimental Double VPN setup.",
    apkDownload: "Download Android APK",
    releases: "Read release notes and checksums",
    sourceTitle: "Explore the source",
    sourceBody:
      "Read the public code, review the setup scripts or contribute a change on GitHub.",
    source: "View source code",
    installTitle: "Installing an APK for the first time?",
    choose:
      "Open the release notes. Under Assets, choose the file ending in .apk. A universal APK works across the processor types listed for that release.",
    apkOpen:
      "Open the downloaded file on your phone. If Android asks, allow the app you downloaded it with to install this APK.",
    finish:
      "Once installation finishes, open Rookstride from your apps. You can switch the installation permission off again in Android settings.",
    other: "See other ways to use Rookstride",
    metaTitle: "Android downloads",
  },
  provider: {
    eyebrow: "For VPS providers",
    title: "Give customers a VPN they can run themselves.",
    lead: "Your customers rent a server from you. With Rookstride, they can set up their VPN, give a friend access and remove it later, all from their phone. The software is free and open source.",
    pilot: "Plan a provider pilot",
    roles: "Who controls what?",
    customer: "The customer",
    customerRole:
      "Administers the VPN, chooses who can connect and keeps the server sign-in.",
    family: "Family and friends",
    familyRole:
      "Get their own VPN access. Only the owner needs the server administrator details.",
    host: "Your hosting team",
    hostRole:
      "Provides the server and handles hosting support, plan changes and billing.",
    afterTitle: "What happens after setup?",
    access:
      "When a family member needs access, the owner creates a separate connection for them. If that access ends, the owner can revoke it while everyone else keeps using the VPN.",
    controls:
      "From the app, the owner can also check traffic estimates and adjust AdGuard Home’s DNS filters to block known ad domains. Available controls depend on the VPN method and app release.",
    plan: "The customer keeps their hosting account. If their server or transfer allowance reaches its limit, they can choose a suitable plan with you.",
    route: "When a customer rents two servers",
    pilotTitle: "Start with one plan and a customer guide.",
    pilotBody:
      "A recommendation can be the whole partnership. Choose one server plan and a public Android release. A short pilot will tell your team whether a first-time customer can follow the guide on that combination.",
    releases: "Read the public release notes",
    connect: "Connect on a fresh rental",
    connectBody:
      "Have a tester set up a VPN and open a website through it using the instructions you would give a customer.",
    share: "Share access, then take it back",
    shareBody:
      "Connect a second device as a guest. Revoke the guest’s access and confirm the owner can still reconnect after a restart.",
    support: "Give customers a support path",
    supportBody:
      "Record the tested plan, operating system and app version. In the guide, say where to get help with the rental and where to report a VPN issue.",
    more: "Other interfaces and integrations",
    interfaces:
      "The personal browser app runs on the customer’s computer. It can set up one IKEv2 gateway with AdGuard Home and manage its guest accounts. Customers can practice the steps before renting a server. Assistants can inspect sample setups. A Telegram Mini App is planned.",
    double:
      "For two servers, test the entry and exit together, including reconnection, DNS and what happens if either goes offline. The Android development edition includes this setup.",
    marketplace:
      "If your team wants a first-boot installer or a marketplace listing, review how each customer gets unique keys, how the app takes over management, and who handles updates and recovery. These are options for a future integration.",
    metaDescription:
      "Give customers a way to set up, share and look after a VPN on the servers they rent from you. Explore a Rookstride provider pilot.",
  },
  pilot: {
    title: "Share the pilot with your team",
    lead: "Take the test steps and support questions to the people who look after your VPS plans.",
    copy: "Copy the pilot brief",
    read: "Read the pilot brief",
    brief:
      "Rookstride provider pilot\n\nPurpose\nHelp a customer set up and look after a personal VPN on an ordinary VPS rental. Rookstride is free, open-source software. The customer controls access, pays the hosting provider and can change plans there if their needs grow.\n\nFirst trial\nChoose one VPS plan and a public Android release. Ask a first-time user to set up the VPN using a short guide, connect a second device as a guest, revoke its access and reconnect as the owner after a restart. Test the traffic display and optional DNS ad filtering for the chosen VPN method.\n\nWhat to publish\nRecord the release, operating system and plan that passed the trial. Give customers the tested steps and a clear contact for hosting issues and VPN software issues. A recommendation and guide are enough to start.\n\nPossible follow-up\nTest a two-server route separately, including loss of the link between entry and exit. For a first-boot installer or marketplace listing, agree how to handle unique keys, app enrollment, updates and recovery before offering it to customers.\n\nRelease notes and source",
    copied: "Pilot brief copied.",
    failed: "Open “Read the pilot brief” to select and copy the text.",
  },
  journal: {
    title: "Rookstride journal",
    lead: "Project news, release notes and guides to running your own VPN.",
    empty: "The first article will appear here when it’s published.",
    sample: "Sample article",
    categories: { project: "Project notes", guides: "Guides" },
    metaTitle: "Journal",
  },
  article: {
    back: "← All journal articles",
  },
  comics: {
    title: "Rook’s comics",
    originTitle: "How Rook found his feet",
    originBody:
      "A librarian found a little red bird drawn in the margin of an old atlas, beside a route no one had finished. One stormy night, a drop of lantern oil fell on the page. A courier was stranded. The bird blinked, stepped onto the desk and went to help.",
    originEnd:
      "The librarian gave Rook a scarf and a satchel. On his travels he carries a map, listens to the people who know the roads, and leaves the traveler to choose which way to go.",
    read: "Read the chapter",
    back: "Back to Rook’s comics",
    lead: "Follow Rook beyond the workshop and into the worlds of his illustrated adventures.",
    empty: "No chapters here yet.",
    emptyBody:
      "Published chapters will appear in this library. In the meantime, you can read the project journal.",
    journal: "Read the journal",
    preview:
      "Chapter preview. The full strip will be available here when the reader opens.",
    lanternAlt: "Rook carrying a lantern and a satchel",
  },
  agents: {
    back: "← Other ways to get started",
    title: "Explore VPN setup with your assistant.",
    lead: "Ask your assistant what it would do with a fresh server, or why it should stop when a server’s identity changes. Both exercises use a practice server and need no password.",
    how: "How the connection works",
    tools:
      "Rookstride uses the Model Context Protocol (MCP) to let an assistant inspect the practice server. Choose your assistant above, copy its settings and start the exercise from that app.",
    own: "Ready to use your own server?",
    chooseBody:
      "Keep your server password out of the chat. You can set up a rented server from your browser or Android phone.",
    choose: "Choose how to start",
    details: "Development and compatibility details",
    compatible:
      "The connector runs on this computer and has been tested with an MCP client. The setup instructions follow each assistant’s documentation. Compatibility with each installed app still needs its own check.",
    remoteCompatible:
      "The hosted connector uses Streamable HTTP. Use a version of your assistant that supports this MCP transport.",
    metaTitle: "Use your AI assistant",
    hostedConnector:
      "The assistant connector runs from a local Rookstride checkout. You can explore the same examples in the browser practice workspace.",
    openPractice: "Open practice workspace",
    hostedChooseBody:
      "Keep your server password out of the chat. See the available setup options before connecting a rented server.",
    operatorTitle: "Use your assistant with your own server",
    operatorBody:
      "The local connector supports all ten single-server methods. It can manage accounts, export profiles and remove a VPN. An optional Ubuntu reinstall works on compatible servers. Changes and exports require approval in a separate terminal. Setup instructions are in the Rookstride web checkout.",
  },
  mcpLanding: {
    title: "Connect your AI assistant",
    intro:
      "Use this MCP endpoint to connect Rookstride to Codex, Claude Code, Cursor, or Gemini CLI.",
    endpoint: "MCP server URL",
    setup: "Open assistant setup",
    practice: "The connector uses read-only practice examples.",
  },
  assistant: {
    choose: "Choose the assistant you already use.",
    lead: "Each button shows the connection steps for that app.",
    steps: "Show connection steps",
    tools: "Connect the example tools",
    connect: "Connect Rookstride to {host}.",
    practice:
      "These tools use an example server. They cannot set up a real server yet. Once connected, your assistant can inspect the examples and explain the steps.",
    open: "Open {file} in your {host} setup.",
    merge: "Merge in the settings below, keeping your existing settings.",
    reload:
      "Reload your assistant’s MCP connections, then try the example task.",
    settings: "Connection settings for {host}",
    copySettings: "Copy connection settings",
    help: "This local example uses files on this computer. On another machine, use your reviewed checkout path and Node24.22.1+.",
    remoteHelp:
      "These settings connect your assistant to the hosted examples over HTTPS.",
    docs: "Read the official {host} instructions",
    taskHeading: "Give your assistant an example task.",
    copyTask: "Copy an example task",
    draft: "Open a draft in Codex",
    draftHelp:
      "Requires the desktop app and the connection above. This opens a draft for you to review and send; it does not run the task automatically.",
    task: 'Use the rookstride-preview MCP server. First call get_capabilities. Then call inspect_example with address "192.0.2.10" and scenario "fresh". Explain the proposed stages and their limits. Next inspect scenario "changed-key" and explain why it stops. This is an example: do not request credentials, contact servers or execute shell commands.',
    show: "Show setup for {host}",
    settingsLabel: "{host} connection settings",
    settingsCopied:
      "Connection settings for {host} copied. Review them before use.",
    taskCopied: "Example task copied. Review it before using it.",
    copyFailed: "Copy was unavailable. Select the text and copy it manually.",
    feedback:
      "You choose when to connect. No app is installed or opened automatically.",
  },
};
