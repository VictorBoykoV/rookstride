// Original Rookstride action artwork, GPL-3.0-or-later.
// Revision2 head paths/proportions retained; new tools/gestures are website explanation art.
export function RookCharacter({
  action = "look",
}: {
  action?: "look" | "carry" | "build" | "share";
}) {
  return (
    <svg
      viewBox="0 0 320 360"
      fill="none"
      aria-hidden="true"
      className={`rook-character rook-${action}`}
    >
      <ellipse cx="146" cy="343" rx="81" ry="8" fill="#141418" opacity=".1" />
      <g fill="#141418">
        <path d="M109 300 105 332 88 340Q86 346 98 346H130Q136 341 122 335L124 302Z" />
        <path d="m151 301 6 32-13 9q-2 5 8 5h32q8-5-4-9l-13-38Z" />
      </g>
      <path
        fill="#ee3038"
        stroke="#141418"
        strokeWidth="5"
        strokeLinejoin="round"
        d="M98 172C75 196 73 250 86 278C96 305 127 322 155 312C180 308 190 281 187 255C183 226 175 197 158 179Z"
      />
      <path
        fill="#141418"
        d="M96 173C76 170 62 180 39 181l13 9-16 6 32 3c16-4 33-11 38-15Z"
      />
      <path fill="#141418" d="M90 171q36 19 75 0l7 15q-41 19-83 2Z" />
      <path stroke="#c5a376" strokeWidth="10" d="m154 195-52 73" />
      <g fill="#f4f0e7" stroke="#141418" strokeWidth="4">
        <rect x="75" y="258" width="70" height="50" rx="10" />
        <path d="M76 262h67l-4 17q-30 12-60 1Z" />
        <path fill="#c6a168" d="M105 276h12v15h-12Z" />
      </g>
      <path
        className="rook-wing"
        fill="#c91f32"
        stroke="#141418"
        strokeWidth="4"
        strokeLinejoin="round"
        d={
          action === "build" || action === "share"
            ? "M157 198Q186 190 225 203L242 218Q210 240 178 231L157 220Z"
            : "M156 200Q189 211 215 234L202 257Q179 252 151 229Z"
        }
      />
      {action === "look" && (
        <g stroke="#141418" strokeWidth="3" strokeLinejoin="round">
          <path
            fill="#fff"
            d="m170 210 30 10 28-9 27 13-9 56-27-12-28 9-30-11Z"
          />
          <path d="m200 220-9 57m37-66-9 57" opacity=".35" />
          <path
            stroke="#bf2637"
            strokeWidth="4"
            strokeDasharray="5 5"
            d="m174 250 27-11 16 12 24-17"
          />
          <circle cx="241" cy="234" r="5" fill="#ee3038" stroke="none" />
        </g>
      )}
      {action === "carry" && (
        <g stroke="#141418" strokeWidth="4">
          <rect x="166" y="210" width="91" height="76" rx="9" fill="#f5f6f8" />
          <path d="M168 247h87" />
          <circle cx="183" cy="230" r="4" fill="#bf2637" />
          <circle cx="183" cy="266" r="4" fill="#bf2637" />
          <path d="M201 230h38m-38 36h38" />
        </g>
      )}
      {action === "build" && (
        <g
          transform="rotate(18 237 211)"
          stroke="#141418"
          strokeWidth="4"
          strokeLinejoin="round"
        >
          <path fill="#f5f6f8" d="m231 201-5 64q6 9 14 0l4-64Z" />
          <path
            fill="#e1e1e5"
            d="m222 176-10 15 7 20 22 9 18-16-1-18-13 13-13-5 3-18Z"
          />
        </g>
      )}
      {action === "share" && (
        <g stroke="#141418" strokeWidth="3">
          <rect x="218" y="183" width="61" height="43" rx="5" fill="#fff" />
          <circle cx="234" cy="200" r="5" fill="#ee3038" stroke="none" />
          <path stroke="#bf2637" d="M231 213h13m4-14h19m-19 9h14" />
          <path
            stroke="#c6a168"
            strokeWidth="5"
            d="m265 227 11 9 8-8m-8 8-5 5"
          />
        </g>
      )}
      <g className="rook-head" transform="translate(12 -2)">
        <RookHead />
      </g>
    </svg>
  );
}

function RookHead() {
  return (
    <>
      <path
        fill="#EE3038"
        d="M68 78 C55 89 46 109 46 130 C46 168 73 193 110 193 C145 193 170 169 175 145 L209 129 L174 114 C168 91 147 72 122 67 C107 47 89 40 65 43 L79 69 C75 72 71 75 68 78 Z"
      />
      <path
        fill="#FFFFFF"
        d="M126 83 C111 83 105 98 109 114 C112 131 123 141 137 135 C150 130 154 115 148 101 C144 89 136 83 126 83 Z"
      />
      <path
        fill="#141418"
        d="M144 108 A9 13 0 1 1 126 108 A9 13 0 1 1 144 108 Z"
      />
    </>
  );
}

// Close-up drawn for the setup guide. The foreground map covers the torso;
// its open right edge leads into the adjacent sequence of instructions.
export function RookSetupIllustration() {
  return (
    <svg
      viewBox="0 0 300 224"
      width="300"
      height="224"
      fill="none"
      aria-hidden="true"
      focusable="false"
      data-art="rook-setup-map"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path
        fill="#EE3038"
        d="M82 120c-25 9-45 29-53 52-6 18-5 35 7 42 14 9 51 6 74-5l43-26c-2-35-29-66-71-63Z"
      />
      <path
        fill="#141418"
        d="M75 132c-20 4-32 0-46-7l7 13-22-2 18 10-12 4c20 5 38 2 55-7Zm-17 11c15 12 40 19 69 15l-5-14c-20 3-40-3-55-13Z"
      />
      <path
        fill="#141418"
        d="M100 152c-6 22-14 45-26 67l9-1c11-18 21-41 29-66Z"
      />
      <g transform="translate(-22 -31) rotate(9 125 129)">
        <RookHead />
      </g>

      <path
        fill="#BF2637"
        d="M127 168c16-26 30-40 46-47 8-4 20-5 27-1 4 3 4 7-2 10l-19 9-32 35Z"
      />
      <path
        fill="#FFFFFF"
        stroke="#141418"
        strokeWidth="2.5"
        d="m83 135 61 9 59-28 70 16 12 62-70-10-60 28-62-12Z"
      />
      <path fill="#F5F6F8" d="m145 145 57-27 12 65-58 27Z" />
      <path
        stroke="#141418"
        strokeWidth="1.25"
        opacity=".4"
        d="m144 145 11 65m48-92 12 64"
      />
      <path
        stroke="#B5B9BE"
        strokeWidth="1.4"
        d="m98 149 17 3 7 7 9 2m38-9 9-6 16-4m35 23 11-1 9 3 14 1m-98 26 8-6 13-2"
      />
      <path
        stroke="#BF2637"
        strokeWidth="3.5"
        d="M106 184c8-11 13-16 23-15 8 0 13 8 21 7 14-1 17-16 31-19 9-2 19 1 28-2 15-6 20-13 29-12l17 4"
      />
      <circle cx="106" cy="184" r="3.5" fill="#BF2637" />
      <circle
        cx="255"
        cy="147"
        r="5"
        fill="#FFFFFF"
        stroke="#BF2637"
        strokeWidth="3"
      />

      <path
        fill="#BF2637"
        stroke="#141418"
        strokeWidth="2.25"
        d="M46 169c1 15 9 28 23 32 10 3 20 1 29-3l9-6c3-3 1-7-4-7l-8 1 7-5c3-3 1-6-3-6-7 0-16 4-22 5-9-8-15-13-21-14"
      />
      <path stroke="#141418" strokeWidth="1.75" d="m78 193 15-5" />
    </svg>
  );
}
