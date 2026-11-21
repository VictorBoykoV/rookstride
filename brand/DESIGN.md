# Rook mark revision 2

13 October 2026. Feedback: the first mark was hard to recognize as a bird before reading the comics; its three sharp protrusions felt ambiguous. Preserve the colors and Rookstride name.

The revision uses one swept crest, a round head/chin, a longer clearly projecting beak, and a forward-facing oval eye. Three filled shapes work at small sizes without fine outlines. The original is retained in rook-v1.svg for comparison. Native SVG and Android vector paths are identical.

Rook is a fictional red navigator, not a zoological illustration. A real rook is a corvid; a male chicken is a rooster. The name and existing comic character stay intact.

The website and Android source use the new mark. Experimental 0.2.0 builds include it in the signed APK. The published 0.1.0-alpha2 APK and its genuine screenshots retain the original mark; no existing binary has been relabeled or silently replaced. The two gateway repositories carry the same revision in their Android integration links, with its separate artwork license.

Signal red #EE3038; white #FFFFFF; charcoal #141418. Warm paper #F4F0E7 is a background/reversed-mark variant. Original brand assets are GPL-3.0-or-later.

## Interface system — app and future website alignment

Updated 18 October 2026. These rules are canonical for new interfaces. The
existing website is not restyled by the Android change.

- Signal red `#EE3038` belongs to the mark and large accents. Action red
  `#BF2637` provides readable small white button text. Ink `#141418`, muted
  `#5C616B`, white surfaces, cool canvas `#F5F6F8`; warm paper remains for stories.
- Use an 8dp spacing rhythm with 4dp adjustments; 20dp page gutters. Standard
  cards have 16dp corners, action buttons 12dp. A connection hero may use 24dp.
- Bottom navigation is one continuous white surface with a 1dp upper divider,
  four equal destinations (VPNs, Split tunneling, Journal, Settings), 22dp original icons and 12sp labels. Selection has a
  short red upper indicator and a selected accessibility state. Its containers
  have square corners; they are not adjacent pill buttons. Labels keep a consistent row. Minimum height
  is 68dp and grows with text. Keep navigation independent of server-job locks.
- Primary actions have at least 48dp targets. Separate neighboring buttons by
  10dp. Custom dialog bodies scroll; native actions remain outside the scroll.
- Home lists managed servers once. A server owns its protocol list; installed
  protocols come first, alphabetically, then uninstalled protocols alphabetically.
  Imported connections and two-server routes retain their distinct capabilities.
- A left swipe reveals a labeled 72dp trash target. It never deletes directly.
  Long press starts live server reordering; the accessible reorder actions remain. Removal from the
  phone and uninstalling server software use distinct, explicit confirmations.
- Accounts have direct Edit and Share access actions. Display names are editable;
  login/key identity remains stable. Deletion requires confirmation.
- Rook belongs beside connection/progress explanations. He never replaces a
  measured status, participates in a password field or decorates a destructive
  confirmation. Honor disabled animations.

## Persistent identity and scope — 19 October 2026

Keep the red bird mark and Rookstride wordmark at a fixed leading position on
all native administration screens. Put the app-preferences gear at the trailing
edge. Back and the current server/protocol context occupy a second row; opening
a child screen must not shift the brand. Add VPN is a secondary full-width action
under Your VPNs. A warm paper welcome with the map pose and a short route-themed
line gives home its character. Connection, waiting and success poses retain
explicit status text; password and removal dialogs have no mascot illustration.
Separate app preferences, server settings and protocol settings in navigation and
copy. A protocol card's information target is at least 48dp and opens an
explanation without selecting or installing that protocol.

At compact widths or enlarged text, reduce the decorative welcome pose and use a
26sp base headline so the first saved server stays visible. Respect the system
font scale; content remains scrollable and no text is ellipsized.

## Operation feedback — private alpha11

Use the map/celebrate helper beside the active or recent connection. Short
server work uses the wait pose beside a real task label and an indeterminate
spinner; do not imply a measured percentage. Installation checkpoints use red
completed markers and one active spinner. Honor reduced motion. Completion uses
the celebrate pose, a clear installed message and fixed, spaced next actions.
Rook does not appear inside secret fields or removal confirmations.

## Installation workshop · private alpha21

The app uses fourteen original [installation illustrations](installation/README.md)
with the existing revision2 head and ambassador body. Each recipe checkpoint has
a distinct task prop: cables, inspection glass, plans, shield, controls, power,
route check, delivery, monitoring, far station, two bridge ends, gate or health
report. Paused work uses the patient helper; completed work uses the celebration.
Keep the explicit checkpoint text beside the decorative image. Gentle motion
follows Android's animation setting and never represents elapsed or estimated
progress. Website and story artwork remain separate surfaces.

### Alpha22 navigation and app selection

The header keeps the brand and Activity bell; Settings has one stable bottom-tab
location. Help and licenses open from Settings and return there. Reselecting the
current tab preserves its page and scroll. Home server management uses a 56dp cog
aligned with the server title; the remaining card surface expands known VPNs.
Split tunneling describes the selected mode and shows system app icons in its
bounded searchable picker. Icon caches belong to the dialog and stay bounded.

## Android utility surfaces — 3 November 2026

The app uses cool canvas `#F5F6F8`, white surfaces, charcoal `#141418`, muted
`#5C616B` and borders `#E0E3E8`. Action red `#BF2637` keeps white controls readable;
Rook retains signal red. Warm paper belongs to story art, not utility screens.
Quick connections use a red card, a white action and Rook as a small helper.
Visible gutters distinguish neighboring carousel cards; recent/active comes first,
with favorites following. Full protocol titles wrap; connection-state changes
never resize the carousel. Activity is a dated list of compact rows. The native cog is an original rounded six-tooth vector with equal rotational spacing.
This app refinement does not restyle the existing website or change the mark.

### Quick-connection follow-through · private alpha28

Recent/Favorite is a visible translucent label above the full protocol title.
Show the saved server address on its own line; Double VPN includes both endpoints.
Connection status remains explicit beside the white action. Reserve card height
from catalog/window/font/endpoint text, never from connection state. Preserve the
existing swipe gutters and stable Home scroll. Cycle five original helper poses
across the idle cards; use waiting/celebration for the active transition/result.
No random image requests or new network dependency is introduced.

Both Home shortcuts and installed server-protocol cards have explicit 48dp settings
cogs. Name/body taps still open the same tools; Connect and Details stay separate.
Use the same rounded six-tooth cog throughout. Keep reviewed Remove VPN setups
separate from routine Refresh / Server access. Activity clearing has a short
Cancel/Clear confirmation; cancelling must preserve history and its screen.

### Sign-in and removal controls · private alpha29

The second idle quick-card pose holds the existing preparation book; the other
four props and active-state poses remain. Password fields use original eye/eye-off
vectors in a48dp end action. Preserve text/caret and default masking. Remove server
from this phone is visible in Server tools and is distinct from remote Remove VPN
setups; use the existing local-only confirmation. Public-certificate IKEv2 accounts
share readable sign-in text when the creation password is available. Private trust
continues to share the .sswan profile. These refinements do not restyle the website.

On a keyboard viewport below240dp, collapse native dialog titles temporarily and
restore them on keyboard close. Allocate the scroll body from visible chrome;
keep native actions outside it so password eye targets remain reachable.
