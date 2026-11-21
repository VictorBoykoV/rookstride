import { getMessages } from "@/i18n/messages";
import Link from "next/link";
import { Icon } from "@/components/icons";
import { articleCategory, articles } from "@/lib/content";
import { publicPageMetadata } from "@/lib/site-discovery";

const copy = getMessages("site").journal;

export const dynamic = "force-dynamic";
export function generateMetadata() {
  return publicPageMetadata("/journal", copy.metaTitle, copy.lead);
}
export default async function Journal() {
  const posts = await articles();
  return (
    <main className="page-width inner-page">
      <header className="page-intro">
        <h1>{copy.title}</h1>
        <p>{copy.lead}</p>
      </header>
      <div className="article-list">
        {posts.map((post) => (
          <Link
            className="article-row"
            href={`/journal/${post.slug}`}
            key={post.id}
          >
            <div>
              <span className="tag">{articleCategory(post)}</span>
              <h2>{post.title}</h2>
              <p>{post.summary}</p>
            </div>
            <Icon name="arrow" />
          </Link>
        ))}
      </div>
      {posts.length === 0 && <p className="empty-state">{copy.empty}</p>}
    </main>
  );
}
