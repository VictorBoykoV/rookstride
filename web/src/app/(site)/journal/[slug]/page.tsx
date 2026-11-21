import { getMessages } from "@/i18n/messages";
import Link from "next/link";
import { notFound } from "next/navigation";
import { articleBySlug, articleCategory } from "@/lib/content";
import { publicPageMetadata } from "@/lib/site-discovery";

const copy = getMessages("site").article;

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Props) {
  const { slug } = await params;
  const post = await articleBySlug(slug);
  if (!post || post.sampleContent) return {};
  return publicPageMetadata(
    `/journal/${encodeURIComponent(post.slug)}`,
    post.title,
    post.summary,
  );
}

export default async function ArticlePage({ params }: Props) {
  const { slug } = await params;
  const post = await articleBySlug(slug);
  if (!post) notFound();
  return (
    <main className="page-width inner-page">
      <article className="reading-page">
        <Link className="back-link" href="/journal">
          {copy.back}
        </Link>
        <p className="eyebrow">{articleCategory(post)}</p>
        <h1>{post.title}</h1>
        <p className="article-lead">{post.summary}</p>
        <div className="article-body">
          {post.body.split(/\n\s*\n/).map((paragraph, index) => (
            <p key={index}>{paragraph}</p>
          ))}
        </div>
      </article>
    </main>
  );
}
