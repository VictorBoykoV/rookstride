import { getMessages } from "@/i18n/messages";
import { getPayload } from "payload";
import { cache } from "react";
import config from "@payload-config";

export type Article = {
  id: number;
  title: string;
  slug: string;
  summary: string;
  body: string;
  category: string;
  publishedAt: string;
  sampleContent?: boolean;
};
export const articlePageSize = 30;

export function articleCategory(article: Article) {
  const copy = getMessages("site").journal;
  if (article.sampleContent) return copy.sample;
  if (article.category === "project" || article.category === "guides") {
    return copy.categories[article.category];
  }
  return article.category;
}

export async function articles(page = 1): Promise<Article[]> {
  const payload = await getPayload({ config });
  const result = await payload.find({
    collection: "articles",
    page,
    limit: articlePageSize,
    sort: "-publishedAt",
    overrideAccess: false,
    draft: false,
  });
  return result.docs as unknown as Article[];
}

export const articleBySlug = cache(async (slug: string) => {
  const payload = await getPayload({ config });
  const result = await payload.find({
    collection: "articles",
    where: { slug: { equals: slug } },
    limit: 1,
    overrideAccess: false,
    draft: false,
  });
  return result.docs[0] as unknown as Article | undefined;
});

export async function chapters(page = 1) {
  const payload = await getPayload({ config });
  return payload.find({
    collection: "chapters",
    depth: 1,
    page,
    sort: "-createdAt",
    limit: 30,
    overrideAccess: false,
    draft: false,
  });
}

// A missing or private page makes the entire chapter ineligible to feature.
export function readableChapter(doc: Record<string, unknown>) {
  if (
    doc._status !== "published" ||
    doc.editorialApproved !== true ||
    typeof doc.title !== "string" ||
    typeof doc.slug !== "string" ||
    typeof doc.summary !== "string" ||
    !Array.isArray(doc.pages) ||
    !doc.pages.length
  )
    return null;

  const pages = [];
  for (const page of doc.pages) {
    const media = page?.image;
    if (
      media?.publicApproved !== true ||
      typeof media.filename !== "string" ||
      !media.filename ||
      typeof media.alt !== "string" ||
      !media.alt.trim()
    )
      return null;
    pages.push({
      src: `/api/media/file/${encodeURIComponent(media.filename)}`,
      alt: media.alt as string,
      caption: typeof page.caption === "string" ? page.caption : "",
    });
  }
  return {
    title: doc.title,
    summary: doc.summary,
    pages,
    href: `/comics/${encodeURIComponent(doc.slug)}`,
  };
}

export async function featuredChapter() {
  let page = 1;
  while (true) {
    const result = await chapters(page);
    for (const doc of result.docs) {
      const story = readableChapter(doc);
      if (story) return story;
    }
    if (!result.nextPage) return null;
    page = result.nextPage;
  }
}

export const chapterBySlug = cache(async (slug: string) => {
  const payload = await getPayload({ config });
  const result = await payload.find({
    collection: "chapters",
    where: { slug: { equals: slug } },
    depth: 1,
    limit: 1,
    overrideAccess: false,
    draft: false,
  });
  return result.docs[0] ? readableChapter(result.docs[0]) : null;
});
