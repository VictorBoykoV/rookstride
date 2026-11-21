import { getMessages } from "@/i18n/messages";
import { publicPageMetadata, publicProjectLinks } from "@/lib/site-discovery";
import Link from "next/link";
import { Icon } from "@/components/icons";
const { download: copy, connect } = getMessages("site");

export function generateMetadata() {
  return publicPageMetadata("/downloads", copy.metaTitle, copy.lead);
}
export default function Downloads() {
  return (
    <main className="page-width inner-page">
      <header className="page-intro">
        <p className="eyebrow">{copy.platform}</p>
        <h1>{copy.title}</h1>
        <p>{copy.lead}</p>
      </header>
      <div className="download-grid">
        <section className="download-card">
          <Icon name="phone" />
          <h2>{copy.apkTitle}</h2>
          <p>{copy.apkBody}</p>
          <a
            className="button primary"
            href={publicProjectLinks.androidApk}
            target="_blank"
            rel="noreferrer"
          >
            {copy.apkDownload} <Icon name="external" />
          </a>
          <a className="text-link" href={publicProjectLinks.androidRelease}>
            {copy.releases}
          </a>
        </section>
        <section className="download-card">
          <Icon name="agent" />
          <h2>{copy.sourceTitle}</h2>
          <p>{copy.sourceBody}</p>
          <a
            className="button secondary"
            href={publicProjectLinks.androidRepository}
            target="_blank"
            rel="noreferrer"
          >
            {copy.source} <Icon name="external" />
          </a>
        </section>
      </div>
      <section className="download-help">
        <h2>{copy.installTitle}</h2>
        <ol>
          <li>{copy.choose}</li>
          <li>{copy.apkOpen}</li>
          <li>{copy.finish}</li>
        </ol>
        <Link className="text-link" href="/connect">
          {connect.navLabel} <Icon name="arrow" />
        </Link>
      </section>
      <Link className="text-link" href="/start">
        {copy.other} <Icon name="arrow" />
      </Link>
    </main>
  );
}
