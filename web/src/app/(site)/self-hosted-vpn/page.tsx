import Link from "next/link";
import { getMessages } from "@/i18n/messages";
import { publicPageMetadata, publicProjectLinks } from "@/lib/site-discovery";
import { publicSiteOrigin } from "@/lib/web-runtime.mjs";
import { NetworkScene } from "@/components/network-scene";
import { singleProtocolCatalog } from "@/lib/gateway-input.mjs";

const { selfHosted: copy, connect } = getMessages("site");
const source = publicProjectLinks.androidRepository;
const path = "/self-hosted-vpn";

export function generateMetadata() {
  return publicPageMetadata(path, copy.metaTitle, copy.lead);
}

export default function SelfHostedVpn() {
  const origin = publicSiteOrigin();
  const software = origin && {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "Rookstride",
    url: new URL(path, origin).href,
    description: copy.lead,
    operatingSystem: "Android",
    downloadUrl: new URL("/downloads", origin).href,
    isAccessibleForFree: true,
    sameAs: source,
  };

  return (
    <main className="page-width inner-page">
      {software && (
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify(software).replace(/</g, "\\u003c"),
          }}
        />
      )}
      <article className="reading-page vpn-guide">
        <h1>{copy.title}</h1>
        <p className="article-lead">{copy.lead}</p>
        <a className="button secondary" href="#route-comparison">
          {copy.comparison.title}
        </a>
        <div className="article-body">
          <section>
            <h2>{copy.one.title}</h2>
            <p>{copy.one.body}</p>
            <NetworkScene mode="single" />
            <p>{copy.one.details}</p>
            <a
              className="text-link"
              href={publicProjectLinks.singleGateway}
            >
              {copy.singleGuide}
            </a>
          </section>
          <section>
            <h2>{copy.two.title}</h2>
            <p>{copy.two.body}</p>
            <NetworkScene mode="two" />
            <p>{copy.two.details}</p>
            <div className="button-row">
              <a className="text-link" href={publicProjectLinks.doubleGateway}>
                {copy.doubleGuide}
              </a>
              <a className="text-link" href={publicProjectLinks.androidPairGuide}>
                {copy.androidPairGuide}
              </a>
            </div>
          </section>
          <section>
            <h2 id="route-comparison">{copy.comparison.title}</h2>
            <div className="vpn-comparison">
              <table aria-labelledby="route-comparison">
                <thead>
                  <tr>
                    {copy.comparison.columns.map((column) => (
                      <th key={column} scope="col">
                        {column}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {copy.comparison.rows.map(([label, single, double]) => (
                    <tr key={label}>
                      <th scope="row">{label}</th>
                      <td>{single}</td>
                      <td>{double}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section>
            <h2>{copy.methods.title}</h2>
            <p>{copy.methods.body}</p>
            <ul>
              <li>{getMessages("manage").protocol.ikev2}</li>
              {Object.values(singleProtocolCatalog).map(({ name }) => (
                <li key={name}>{name}</li>
              ))}
            </ul>
          </section>
          <section>
            <h2>{copy.filter.title}</h2>
            <p>{copy.filter.body}</p>
          </section>
          <section>
            <h2>{copy.assistants.title}</h2>
            <p>{copy.assistants.body}</p>
            <Link className="text-link" href="/agents">
              {copy.agentGuide}
            </Link>
          </section>
        </div>
        <section>
          <h2>{connect.title}</h2>
          <p>{connect.lead}</p>
          <Link className="button secondary" href="/connect">
            {connect.navLabel}
          </Link>
        </section>
        <a className="text-link" href={source}>
          {copy.source}
        </a>
      </article>
    </main>
  );
}
