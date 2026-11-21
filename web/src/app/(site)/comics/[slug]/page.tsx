import Link from "next/link";
import { notFound } from "next/navigation";
import { getMessages } from "@/i18n/messages";
import { chapterBySlug } from "@/lib/content";
import { publicPageMetadata } from "@/lib/site-discovery";

export const dynamic = "force-dynamic";

type Props = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Props) {
  const { slug } = await params;
  const story = await chapterBySlug(slug);
  if (!story) return {};
  return publicPageMetadata(
    story.href,
    story.title,
    story.summary,
    story.pages[0].src,
  );
}

export default async function ChapterPage({ params }: Props) {
  const { slug } = await params;
  const story = await chapterBySlug(slug);
  if (!story) notFound();
  return (
    <main className="page-width inner-page">
      <article className="reading-page">
        <Link className="back-link" href="/comics">
          {getMessages("site").comics.back}
        </Link>
        <h1>{story.title}</h1>
        <p className="article-lead">{story.summary}</p>
        {story.pages.map((page, index) => (
          <figure className="chapter-page" key={index}>
            <img
              src={page.src}
              alt={page.alt}
              loading={index === 0 ? "eager" : "lazy"}
            />
            {page.caption && <figcaption>{page.caption}</figcaption>}
          </figure>
        ))}
      </article>
    </main>
  );
}
