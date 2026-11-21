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
          <div>
            <h2>{copy.apkTitle}</h2>
            <p>{copy.apkBody}</p>
          </div>
          <div className="download-actions">
            <a className="button primary" href={publicProjectLinks.androidApk} download>
              {copy.apkDownload} <Icon name="download" />
            </a>
            <div className="download-links">
              <a className="text-link" href={publicProjectLinks.androidApkGitHub}>
                {copy.apkGitHub}
              </a>
              <a className="text-link" href={publicProjectLinks.androidApkUniversal}>
                {copy.apkUniversal}
              </a>
            </div>
          </div>
        </section>
        <section className="download-card">
          <Icon name="agent" />
          <div>
            <h2>{copy.sourceTitle}</h2>
            <p>{copy.sourceBody}</p>
          </div>
          <div className="download-actions">
            <a
              className="button secondary"
              href={publicProjectLinks.androidRepository}
              target="_blank"
              rel="noreferrer"
            >
              {copy.source} <Icon name="external" />
            </a>
            <a className="text-link" href={publicProjectLinks.androidRelease}>
              {copy.releases}
            </a>
          </div>
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
