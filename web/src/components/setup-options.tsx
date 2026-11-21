import Link from "next/link";
import { getMessages } from "@/i18n/messages";
import {
  hostedPilotVisible,
  personalGatewayEnabled,
} from "@/lib/web-runtime.mjs";
import { Icon } from "./icons";
import styles from "./site-guide.module.css";

const copy = getMessages("site").start;

export function SetupOptions({
  showTelegram = false,
}: {
  showTelegram?: boolean;
}) {
  const hosted = hostedPilotVisible();
  const personal = personalGatewayEnabled();
  const browser = hosted
    ? copy.browserHosted
    : personal
      ? copy.browser
      : copy.browserPractice;
  const clients = [
    {
      icon: "browser",
      link: hosted ? "/vpn" : personal ? "/manage" : "/manage#practice",
      ...browser,
    },
    { icon: "phone", link: "/downloads", ...copy.android },
    { icon: "agent", link: "/agents", ...copy.assistant },
  ];
  const Heading = showTelegram ? "h2" : "h3";
  const layout = showTelegram ? styles.channels : styles.channelPins;
  const item = showTelegram ? styles.channel : styles.channelPin;

  return (
    <div className={layout}>
      {clients.map((client) => (
        <Link
          className={`${item} ${styles.channelLink}`}
          key={client.link}
          href={client.link}
        >
          <div className={styles.channelName}>
            {showTelegram ? (
              <Icon name={client.icon} />
            ) : (
              <span className={styles.channelMarker}>
                <Icon name={client.icon} />
              </span>
            )}
            <Heading>{client.name}</Heading>
          </div>
          {showTelegram && <p>{client.description}</p>}
          <span className={`text-link ${styles.channelAction}`}>
            {client.action} <Icon name="arrow" />
          </span>
        </Link>
      ))}
      {showTelegram && (
        <section className={styles.channel}>
          <div className={styles.channelName}>
            <Icon name="message" />
            <h2>{copy.telegram}</h2>
          </div>
          <p>{copy.telegramBody}</p>
          <span className={styles.planned}>{copy.planned}</span>
        </section>
      )}
    </div>
  );
}
