import Link from "next/link";
import { Icon } from "@/components/icons";
import { getMessages } from "@/i18n/messages";
import { publicPageMetadata } from "@/lib/site-discovery";
import styles from "./connect.module.css";

const copy = getMessages("site").connect;

export function generateMetadata() {
  return publicPageMetadata("/connect", copy.metaTitle, copy.lead);
}

export default async function ConnectGuide({
  searchParams,
}: {
  searchParams: Promise<{ device?: string | string[] }>;
}) {
  const { device } = await searchParams;
  const selected =
    copy.devices.find(({ id }) => id === device) ?? copy.devices[0];
  return (
    <main className={`page-width inner-page ${styles.guide}`}>
      <header className={styles.intro}>
        <h1>{copy.title}</h1>
        <p>{copy.lead}</p>
      </header>

      <nav className={styles.devices} aria-label={copy.deviceNav}>
        {copy.devices.map((device) => (
          <Link
            key={device.id}
            href={`/connect?device=${device.id}`}
            className={styles.jump}
            aria-current={selected.id === device.id ? "page" : undefined}
            prefetch={false}
            scroll={false}
          >
            <Icon name={device.icon} />
            {device.title}
          </Link>
        ))}
      </nav>

      {selected.id === "android" && (
        <section className={styles.android} aria-labelledby="rookstride-title">
          <div>
            <h2 id="rookstride-title">{copy.androidTitle}</h2>
            <p>{copy.androidSummary}</p>
          </div>
          <Link className="button primary" href="/downloads">
            {copy.getAndroid} <Icon name="arrow" />
          </Link>
        </section>
      )}

      <section
        key={selected.id}
        className={styles.device}
        id="methods"
        aria-labelledby="device-methods"
      >
        <h2 id="device-methods">
          {selected.title} · {copy.methodTitle}
        </h2>
        <div className={styles.methods}>
          {selected.methods.map((method, index) => (
            <details
              className={styles.method}
              key={method.title}
              name="connection-method"
              open={index === 0}
            >
              <summary className={styles.methodSummary}>
                <span>
                  <strong>{method.title}</strong>
                  <span className={styles.input}>{method.input}</span>
                </span>
                <Icon className={styles.down} name="arrow" />
              </summary>
              <div className={styles.methodBody}>
                <ol className={styles.steps}>
                  {method.steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
                {method.links.length > 0 && (
                  <ul className={styles.links}>
                    {method.links.map(({ label, href }) => (
                      <li key={href}>
                        <a className="text-link" href={href}>
                          {label}{" "}
                          <Icon
                            name={href.startsWith("/") ? "arrow" : "external"}
                          />
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </details>
          ))}
        </div>
      </section>

      <section className={styles.notes} aria-labelledby="before-title">
        <h2 id="before-title">{copy.beforehand}</h2>
        <p>{copy.profileHelp}</p>
        <p>{copy.ikeTrust}</p>
        <p>{copy.awgVersion}</p>
        <Link className="text-link" href="/start">
          {copy.setupLink} <Icon name="arrow" />
        </Link>
      </section>
      <section className={styles.notes} aria-labelledby="check-title">
        <h2 id="check-title">{copy.checkTitle}</h2>
        <p>{copy.checkBody}</p>
      </section>
    </main>
  );
}
