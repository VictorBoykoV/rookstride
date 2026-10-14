# Installation, with a place to return

Rookstride keeps the chosen recipe visible throughout setup:

| Path | Checkpoints |
| --- | ---: |
| Fresh single-server IKEv2 gateway | 5 |
| Enroll compatible gateway management | 4 |
| IKEv2 entry → AmneziaWG exit pair | 8 |

The bar counts completed checkpoints. It does not invent package-download percentages.
The current phase comes from the actual coordinator/server job. Planning ranges are
broad, unbenchmarked estimates; package mirrors, kernel preparation, SSH availability,
and a reboot can take longer. Elapsed time is shown separately.

## Browse while the work continues

Stories, Guide, People, Sessions, and Gateways remain reachable. Server-changing
controls stay disabled during an installation. Tap the progress shortcut on any tab,
or the installation notification, to reopen the step view. Rook changes roles from
map-reader to bridge-builder, lantern-guide, and celebration; his motion respects
Android's animation setting.

The user starts a separate Android `dataSync` foreground service while the app is
visible. It owns SSH transfer/polling, independent of the Activity. Screen recreation,
tab changes, and ordinary backgrounding do not cancel it. A notification returns to
progress. The service uses a bounded partial wake lock, and stops after success,
failure, required identity confirmation, or a required owned reboot. No password or
private key is put in an Intent or the progress preference file.

Force-stop, process death, Android's foreground-service budget, or an OEM policy can
end phone polling. Detached VPS jobs continue subject to their own server lifecycle.
The next launch labels saved running progress as needing inspection; it never silently
starts a fresh install. Resume uses the recorded job/owner, independent SSH pins, and
the original fresh-install protections. Existing two-hop pairs still require an explicit
upgrade if their installer bundle differs. The UI changes do not alter that bundle.

## Reading and narration

The app bundles five worlds, fifty four-page chapters, the original five strip comics,
Rook's lore, and cultural notes. No account or story-download connection is needed.
The reader is an asset-only HTTPS-origin WebView: file/content access and network
loads are disabled; only owned bundled assets are served. Tapping a cultural HTTPS source opens it in the external browser, outside the privileged WebView. Leaving Stories stops
narration, preserves the page URL, and releases the old WebView.

Press Listen to use an installed English offline Android voice. If none is available,
install a voice through Android's speech settings. Narration highlights the illustrated
scene and, when the voice supplies word ranges, the spoken word. Pages advance only
within the current chapter. At its end, the reader waits for a click on the next chapter.
Pause resumes from the beginning of the current page. Manual turns stop narration.
Website narration uses browser/device voices; remote voices are explicitly labeled.
No prerecorded voice performance is claimed.

## Implementation sources

- [Foreground-service types](https://developer.android.com/develop/background-work/services/fgs/service-types)
- [Launch a foreground service](https://developer.android.com/develop/background-work/services/fgs/launch)
- [Android foreground-service timeouts](https://developer.android.com/develop/background-work/services/fgs/timeout)
- [Android utterance progress and word ranges](https://developer.android.com/reference/android/speech/tts/UtteranceProgressListener)
- [Web speech boundary events](https://developer.mozilla.org/en-US/docs/Web/API/SpeechSynthesisUtterance/boundary_event)

Tests distinguish the real background service with bounded transport fixtures, the
real offline WebView with deterministic voice events, an available browser voice,
and previous provider deployment evidence. A fixture is not a fresh VPS deployment
or an audible physical-device test.
