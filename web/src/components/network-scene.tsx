"use client";
import { useEffect, useId, useRef, useState } from "react";
import { useLanguage, useMessages } from "@/i18n/client";
import { Icon } from "./icons";
import styles from "./route-guide.module.css";

export type RouteMode = "single" | "two";

const devices = ["phone", "laptop", "desktop"] as const;
const activities = ["message", "call", "book"] as const;
type Device = (typeof devices)[number];
type MapPoint = "device" | "entry" | "exit" | "filter" | "internet";
type MapSlot = MapPoint | "single";

// Artwork uses the centres of the equal grid tracks. Labels are HTML and can
// wrap or grow without changing the route or scaling the type.
function RouteLines({ compact }: { compact: boolean }) {
  return (
    <svg
      className={compact ? styles.compactLines : styles.wideLines}
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      focusable="false"
      aria-hidden="true"
    >
      <path
        className={styles.direct}
        data-leg="direct"
        d={compact ? "M25 16.667V50" : "M12.5 75H50"}
      />
      <path
        className={styles.intended}
        data-leg="intended"
        d={compact ? "M25 50V83.333" : "M50 75H87.5"}
      />
      <path
        className={styles.vpn}
        data-leg="vpn"
        d={
          compact
            ? "M25 16.667H72Q75 16.667 75 19.667V80.333Q75 83.333 72 83.333H25"
            : "M12.5 75V29Q12.5 25 14.5 25H85.5Q87.5 25 87.5 29V75"
        }
      />
    </svg>
  );
}

export function NetworkScene({ mode }: { mode: RouteMode }) {
  const { diagram } = useMessages("route");
  const { tag, dir } = useLanguage("route");
  const two = mode === "two";

  const [deviceType, setDeviceType] = useState<Device>("phone");
  const [selected, setSelected] = useState<MapPoint | null>(null);
  const opener = useRef<HTMLButtonElement | null>(null);
  const popup = useRef<HTMLDialogElement>(null);
  const dialogId = useId();
  const titleId = useId();
  const descriptionId = useId();
  const titles = {
    device: diagram.device,
    entry: diagram.entry,
    single: diagram.server,
    exit: diagram.exit,
    filter: diagram.provider,
    internet: diagram.internet,
  };
  const point = selected ?? "device";
  const detail = point === "entry" && !two ? "single" : point;
  useEffect(() => {
    if (selected && !popup.current?.open) popup.current?.showModal();
  }, [selected]);
  function explore(point: MapPoint, trigger: HTMLButtonElement) {
    opener.current = trigger;
    setSelected(point);
  }
  function restoreFocus() {
    setSelected(null);
    opener.current?.focus({ preventScroll: true });
  }
  // Both server layouts contribute their intrinsic text heights to the same
  // grid. The unused slots only measure text; they have no accessible controls.
  function node(
    slot: MapSlot,
    icon: string,
    subtitle?: string,
    visible = true,
  ) {
    const id = slot === "single" ? "entry" : slot;
    const noteId = dialogId + "-" + slot;
    const content = (
      <>
        <Icon
          name={icon}
          className={styles.glyph}
          data-device={id === "device" ? deviceType : undefined}
        />
        <span className={styles.name}>{titles[slot]}</span>
        {subtitle && (
          <span className={styles.note} id={visible ? noteId : undefined}>
            {subtitle}
          </span>
        )}
        {id === "internet" && (
          <span className={styles.activitySymbols} aria-hidden="true">
            {activities.map((activity) => (
              <Icon key={activity} name={activity} />
            ))}
          </span>
        )}
      </>
    );
    if (!visible) {
      return (
        <span
          data-slot={slot}
          className={styles.node}
          dir={dir}
          aria-hidden="true"
        >
          {content}
        </span>
      );
    }
    return (
      <button
        type="button"
        className={styles.node}
        data-slot={slot}
        data-point={id}
        dir={dir}
        aria-label={titles[slot]}
        aria-describedby={subtitle ? noteId : undefined}
        aria-haspopup="dialog"
        aria-controls={dialogId}
        onClick={(event) => explore(id, event.currentTarget)}
      >
        {content}
      </button>
    );
  }
  return (
    <figure
      className={`network-flow flow-selected mode-${mode}`}
      aria-label={diagram.title[mode]}
      lang={tag}
      dir={dir}
    >
      <div className={styles.map} data-mode={mode} dir="ltr">
        <RouteLines compact={false} />
        <RouteLines compact />
        <i className={styles.firstArrow} aria-hidden="true" />
        {two && <i className={styles.bridgeArrow} aria-hidden="true" />}
        <i className={styles.lastArrow} aria-hidden="true" />
        {node("device", deviceType, diagram.devices[deviceType])}
        {node("single", "server", diagram.gateway, !two)}
        {node("entry", "server", diagram.domestic, two)}
        {node("exit", "server", diagram.abroad, two)}
        {node("internet", "globe")}
        {node("filter", "stop", diagram.providerAction)}
      </div>
      <ol className="sr-only" aria-label={diagram.order}>
        <li>{diagram.deviceDescription}</li>
        <li>{two ? diagram.twoEntry : diagram.singleEntry}</li>
        {two && <li>{diagram.twoExit}</li>}
        <li>{diagram.destination}</li>
      </ol>
      <figcaption className="route-caption">
        <span>{diagram.explore}</span>
        <span className="diagram-key" aria-hidden="true">
          <span className="key-vpn">{diagram.vpnKey}</span>
          <span className="key-direct">{diagram.directKey}</span>
        </span>
      </figcaption>
      <dialog
        ref={popup}
        id={dialogId}
        className={styles.pointDialog}
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        onClose={restoreFocus}
        onClick={(event) => {
          if (event.target === event.currentTarget) event.currentTarget.close();
        }}
      >
        <div className={styles.pointCard}>
          <div className={styles.pointHeading}>
            <h3 id={titleId}>{titles[detail]}</h3>
            <button
              type="button"
              className={styles.close}
              onClick={() => popup.current?.close()}
            >
              {diagram.close}
            </button>
          </div>
          <p id={descriptionId}>{diagram.details[detail]}</p>
          {selected === "device" && (
            <fieldset className={styles.devicePicker}>
              <legend>{diagram.deviceChoice}</legend>
              <div>
                {devices.map((type) => (
                  <label key={type}>
                    <input
                      type="radio"
                      name={dialogId + "-device"}
                      value={type}
                      checked={deviceType === type}
                      onChange={() => setDeviceType(type)}
                    />
                    <Icon name={type} width="24" height="24" />
                    <span>{diagram.devices[type]}</span>
                  </label>
                ))}
              </div>
            </fieldset>
          )}
          {selected === "internet" && (
            <ul className={styles.activities}>
              {activities.map((activity) => (
                <li key={activity}>
                  <Icon name={activity} />
                  {diagram.activities[activity]}
                </li>
              ))}
            </ul>
          )}
        </div>
      </dialog>
    </figure>
  );
}
