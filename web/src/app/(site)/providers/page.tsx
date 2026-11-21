import { getMessages } from "@/i18n/messages";
import Link from "next/link";
import { Icon } from "@/components/icons";
import { NetworkScene } from "@/components/network-scene";
import { PartnerBrief } from "@/components/partner-brief";
import { publicPageMetadata } from "@/lib/site-discovery";
import styles from "./providers.module.css";

const { provider: copy, demo } = getMessages("site");

export function generateMetadata() {
  return publicPageMetadata("/providers", copy.eyebrow, copy.metaDescription);
}

export default function Providers() {
  return (
    <main className={`page-width inner-page ${styles.page}`}>
      <header className={styles.hero}>
        <div>
          <p className="section-kicker">{copy.eyebrow}</p>
          <h1>{copy.title}</h1>
          <p className={styles.lead}>{copy.lead}</p>
          <div className="button-row">
            <a className="button primary" href="#plan-a-pilot">
              {copy.pilot} <Icon name="arrow" />
            </a>
            <Link className="button secondary" href="/manage#practice">
              {demo.action} <Icon name="browser" />
            </Link>
          </div>
        </div>

        <section className={styles.ownership} aria-labelledby="ownership-title">
          <h2 id="ownership-title">{copy.roles}</h2>
          <dl>
            <div>
              <dt>{copy.customer}</dt>
              <dd>{copy.customerRole}</dd>
            </div>
            <div>
              <dt>{copy.family}</dt>
              <dd>{copy.familyRole}</dd>
            </div>
            <div>
              <dt>{copy.host}</dt>
              <dd>{copy.hostRole}</dd>
            </div>
          </dl>
        </section>
      </header>

      <section className={styles.route} aria-labelledby="provider-route-title">
        <div>
          <h2 id="provider-route-title">{copy.afterTitle}</h2>
          <p>{copy.access}</p>
          <p>{copy.controls}</p>
          <p>{copy.plan}</p>
        </div>
        <div className={styles.routeFigure}>
          <h3>{copy.route}</h3>
          <NetworkScene mode="two" />
        </div>
      </section>

      <section
        className={styles.pilot}
        id="plan-a-pilot"
        aria-labelledby="pilot-title"
      >
        <div>
          <h2 id="pilot-title">{copy.pilotTitle}</h2>
          <p>{copy.pilotBody}</p>
          <a
            className={styles.textLink}
            href="https://github.com/VictorBoykoV/rookstride/releases"
          >
            {copy.releases} <Icon name="external" />
          </a>
        </div>
        <div>
          <ol className={styles.steps}>
            <li>
              <h3>{copy.connect}</h3>
              <p>{copy.connectBody}</p>
            </li>
            <li>
              <h3>{copy.share}</h3>
              <p>{copy.shareBody}</p>
            </li>
            <li>
              <h3>{copy.support}</h3>
              <p>{copy.supportBody}</p>
            </li>
          </ol>
          <details className={styles.details}>
            <summary>{copy.more}</summary>
            <p>{copy.interfaces}</p>
            <p>{copy.double}</p>
            <p>{copy.marketplace}</p>
          </details>
        </div>
      </section>
      <PartnerBrief />
    </main>
  );
}
