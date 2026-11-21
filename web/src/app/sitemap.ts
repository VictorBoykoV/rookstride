import type { MetadataRoute } from "next";
import {
  articlePageSize,
  articles,
  chapters,
  readableChapter,
} from "@/lib/content";
import {
  indexableSitePaths,
  isSafePathSegment,
  publicSiteOrigin,
} from "@/lib/web-runtime.mjs";

export const dynamic = "force-dynamic";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const origin = publicSiteOrigin();
  if (!origin) return [];
  const paths = [...indexableSitePaths];
  for (let page = 1; ; page++) {
    const posts = await articles(page);
    for (const post of posts) {
      if (!post.sampleContent && isSafePathSegment(post.slug))
        paths.push(`/journal/${encodeURIComponent(post.slug)}`);
    }
    if (posts.length < articlePageSize) break;
  }
  for (let page = 1; ; page++) {
    const result = await chapters(page);
    for (const chapter of result.docs) {
      const story = readableChapter(chapter);
      if (story && isSafePathSegment(chapter.slug)) paths.push(story.href);
    }
    if (!result.nextPage) break;
  }
  return paths.map((path) => ({ url: new URL(path, origin).href }));
}
