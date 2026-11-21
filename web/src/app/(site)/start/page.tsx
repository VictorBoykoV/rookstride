import { getMessages } from "@/i18n/messages";
import Link from "next/link";
import { Icon } from "@/components/icons";
import { SetupOptions } from "@/components/setup-options";
import { publicPageMetadata } from "@/lib/site-discovery";
import styles from "@/components/site-guide.module.css";

const { start: copy, connect } = getMessages("site");

export function generateMetadata() {
  return publicPageMetadata("/start", copy.metaTitle, copy.lead);
}
export const dynamic = "force-dynamic";

export default function Start() {
  return (
    <main className={`page-width ${styles.start}`}>
      <header className={styles.startHeading}>
        <p className={styles.motto}>{copy.eyebrow}</p>
        <h1>{copy.title}</h1>
        <p>{copy.lead}</p>
      </header>
      <SetupOptions showTelegram />
      <Link className="text-link" href="/connect">
        {connect.navLabel} <Icon name="arrow" />
      </Link>
      <section
        className={styles.rental}
        id="server-help"
        aria-labelledby="renting-title"
      >
        <div>
          <h2 id="renting-title">{copy.rentalTitle}</h2>
          <p>{copy.rentalBody}</p>
        </div>
        <div>
          <ul>
            <li>{copy.prerequisite}</li>
            <li>{copy.fingerprint}</li>
            <li>{copy.signIn}</li>
          </ul>
          <Link className="text-link" href="/#how-it-works">
            {copy.seeRoute} <Icon name="arrow" />
          </Link>
        </div>
      </section>
    </main>
  );
}
