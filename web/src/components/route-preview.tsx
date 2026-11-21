"use client";
import { useState } from "react";
import { useLanguage, useMessages } from "@/i18n/client";
import { NetworkScene, type RouteMode } from "./network-scene";
import { RookCharacter } from "./rook-character";
import styles from "./site-guide.module.css";

const modes = ["single", "two"] as const;

export function RookJourney() {
  const { guide } = useMessages("route");
  const { tag, dir } = useLanguage("route");
  const [mode, setMode] = useState<RouteMode>("single");

  return (
    <section
      className="rook-journey"
      id="how-it-works"
      aria-labelledby="route-guide-title"
      lang={tag}
      dir={dir}
    >
      <header className="route-supervisor">
        <span className={styles.mapRook}>
          <RookCharacter action="look" />
        </span>
        <div className="rook-speech">
          <h2 id="route-guide-title">{guide.title}</h2>
          <p className={styles.modeIntro} aria-live="polite" aria-atomic="true">
            {modes.map((value) => (
              <span key={value} aria-hidden={value !== mode}>
                {guide.intro[value]}
              </span>
            ))}
          </p>
        </div>
      </header>
      <fieldset className="route-mode-picker">
        <legend>{guide.pickRoute}</legend>
        <div>
          {modes.map((value) => (
            <button
              type="button"
              key={value}
              aria-pressed={mode === value}
              onClick={() => setMode(value)}
            >
              {guide.modes[value]}
            </button>
          ))}
        </div>
      </fieldset>
      <div className="journey-scene">
        <NetworkScene mode={mode} />
      </div>
    </section>
  );
}
