import type { SVGProps } from "react";
export function Icon({
  name,
  ...props
}: SVGProps<SVGSVGElement> & { name: string }) {
  const paths: Record<string, React.ReactNode> = {
    filter: <path d="M3 4h18l-7 8v8l-4-2v-6L3 4Z" />,
    building: (
      <>
        <path d="m3 8 9-5 9 5M3 21h18M5 9v10m7-10v10m7-10v10" />
      </>
    ),
    stop: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="m6 6 12 12" />
      </>
    ),
    book: <path d="M12 5Q7 2 3 4v15q5-2 9 1 4-3 9-1V4q-4-2-9 1Zm0 0v15" />,
    message: <path d="M3 4h18v13h-7l-6 5v-5H3Z" />,
    pencil: <path d="m4 20 2-7L17 2l5 5-11 11-7 2Zm10-15 5 5" />,
    arrow: (
      <>
        <path d="M4 12h16M14 6l6 6-6 6" />
      </>
    ),
    external: (
      <>
        <path d="M7 17 17 7M7 7h10v10" />
      </>
    ),
    server: (
      <>
        <rect x="4" y="3" width="16" height="7" rx="1" />
        <rect x="4" y="14" width="16" height="7" rx="1" />
        <path d="M8 6.5h.01M8 17.5h.01M14 6.5h3M14 17.5h3" />
      </>
    ),
    browser: (
      <>
        <rect x="3" y="4" width="18" height="16" rx="2" />
        <path d="M3 9h18M7 6.5h.01M10 6.5h.01" />
      </>
    ),
    agent: (
      <>
        <path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-13-2 16" />
      </>
    ),
    phone: (
      <>
        <rect x="6" y="2" width="12" height="20" rx="2" />
        <path d="M10 18h4" />
      </>
    ),
    laptop: (
      <>
        <rect x="4.5" y="4" width="15" height="12" rx="1.5" />
        <path d="m4.5 16-2 3a1 1 0 0 0 .8 1.5h17.4a1 1 0 0 0 .8-1.5l-2-3M10 18.5h4" />
      </>
    ),
    desktop: (
      <>
        <rect x="2.5" y="3.5" width="19" height="14" rx="1.5" />
        <path d="M3 14h18m-9 3.5V21m-4 0h8" />
      </>
    ),
    call: (
      <path d="M5 3.5h3l1.5 4-2 1.8a16 16 0 0 0 7.2 7.2l1.8-2 4 1.5v3a1.5 1.5 0 0 1-1.6 1.5C10.6 19.7 4.3 13.4 3.5 5.1A1.5 1.5 0 0 1 5 3.5Z" />
    ),
    guests: (
      <>
        <circle cx="9" cy="8" r="3" />
        <path d="M2.5 20v-1.5a6.5 6.5 0 0 1 13 0V20M16.5 5.5a3 3 0 0 1 0 5.8m1 2.3a5 5 0 0 1 4 4.9V20" />
      </>
    ),
    traffic: <path d="M3 3.5v17h18M7 17v-5m5 5V6m5 11V9" />,
    check: <path d="m5 12 4 4L19 6" />,
    shield: (
      <>
        <path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    copy: (
      <>
        <rect x="8" y="8" width="12" height="13" rx="2" />
        <path d="M15 8V3H3v13h5" />
      </>
    ),
    globe: (
      <>
        <circle cx="12" cy="12" r="9" />
        <ellipse cx="12" cy="12" rx="4" ry="9" />
        <path d="M3 12h18" />
      </>
    ),
  };
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {paths[name] || paths.arrow}
    </svg>
  );
}
