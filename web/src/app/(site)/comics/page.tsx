import { getMessages } from "@/i18n/messages";
import Link from "next/link";
import { chapters, readableChapter } from "@/lib/content";
import { Icon } from "@/components/icons";
import { publicPageMetadata } from "@/lib/site-discovery";

const copy = getMessages("site").comics;

export const dynamic = "force-dynamic";
export function generateMetadata() {
  return publicPageMetadata("/comics", copy.title, copy.lead);
}
export default async function Comics() {
  const result = await chapters();
  return (
    <main className="page-width inner-page">
      <header className="page-intro">
        <h1>{copy.title}</h1>
        <p>{copy.lead}</p>
      </header>
      {result.totalDocs === 0 ? (
        <section className="library-empty">
          <img
            src="/brand/rook-lantern.svg"
            alt={copy.lanternAlt}
            width="180"
            height="200"
          />
          <div>
            <h2>{copy.empty}</h2>
            <p>{copy.emptyBody}</p>
            <Link className="text-link" href="/journal">
              {copy.journal} <Icon name="arrow" />
            </Link>
          </div>
        </section>
      ) : (
        <div className="article-list">
          {result.docs.map((chapter) => {
            const story = readableChapter(chapter);
            return (
              <article className="article-row" key={String(chapter.id)}>
                <div>
                  <span className="tag">{String(chapter.series)}</span>
                  <h2>{String(chapter.title)}</h2>
                  <p>{String(chapter.summary)}</p>
                  {story ? (
                    <Link className="text-link" href={story.href}>
                      {copy.read} <Icon name="arrow" />
                    </Link>
                  ) : (
                    <p className="field-help">{copy.preview}</p>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      )}
      <section className="rook-origin" aria-labelledby="rook-origin">
        <h2 id="rook-origin">{copy.originTitle}</h2>
        <p>{copy.originBody}</p>
        <p>{copy.originEnd}</p>
      </section>
    </main>
  );
}
