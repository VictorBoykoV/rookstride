import { sqliteAdapter } from "@payloadcms/db-sqlite";
import sharp from "sharp";
import { buildConfig, type Access, type Where } from "payload";
import path from "node:path";

const dataDir = process.env.ROOKSTRIDE_DATA_DIR || path.resolve(".private");
const siteMode = process.env.ROOKSTRIDE_HOSTED_SITE;
const hosted = siteMode === "1" || siteMode === "public";
const editor = ({ req }: Parameters<Access>[0]) =>
  (siteMode === undefined || siteMode === "1") && Boolean(req.user);
const approvedChapter: Where = {
  and: [
    { _status: { equals: "published" } },
    { editorialApproved: { equals: true } },
  ],
};
const published: Access = (args) => {
  if (editor(args)) return true;
  const publishedArticles = { _status: { equals: "published" } };
  return hosted
    ? {
        and: [
          publishedArticles,
          {
            or: [
              { sampleContent: { equals: false } },
              { sampleContent: { exists: false } },
            ],
          },
        ],
      }
    : publishedArticles;
};

export default buildConfig({
  secret: process.env.PAYLOAD_SECRET || "",
  telemetry: false,
  email: () => ({
    name: "local-preview",
    defaultFromAddress: "local@example.invalid",
    defaultFromName: "Rookstride local preview",
    sendEmail: async () => {
      throw new Error("Email delivery is disabled in the local preview.");
    },
  }),
  admin: { user: "users", importMap: { baseDir: path.resolve("src") } },
  db: sqliteAdapter({
    client: { url: `file:${path.join(dataDir, "cms.sqlite")}` },
    push: hosted ? false : undefined,
  }),
  sharp,
  upload: { limits: { fileSize: 8 * 1024 * 1024 } },
  typescript: { outputFile: path.join(dataDir, "payload-types.ts") },
  collections: [
    {
      slug: "users",
      auth: true,
      admin: { useAsTitle: "email" },
      access: { read: editor, update: editor, delete: editor, create: editor },
      fields: [],
    },
    {
      slug: "articles",
      admin: { useAsTitle: "title" },
      versions: { drafts: true },
      access: {
        read: published,
        create: editor,
        update: editor,
        delete: editor,
      },
      fields: [
        { name: "title", type: "text", required: true },
        { name: "slug", type: "text", required: true, unique: true },
        { name: "summary", type: "textarea", required: true },
        { name: "body", type: "textarea", required: true },
        {
          name: "category",
          type: "select",
          required: true,
          defaultValue: "project",
          options: [
            { label: "Project notes", value: "project" },
            { label: "Guides", value: "guides" },
          ],
        },
        { name: "publishedAt", type: "date", required: true },
        {
          name: "sampleContent",
          type: "checkbox",
          defaultValue: false,
          admin: {
            description:
              "Marks local example content; readers see an explicit sample label.",
          },
        },
      ],
    },
    {
      slug: "media",
      admin: { useAsTitle: "alt" },
      access: {
        read: (args) =>
          editor(args) ? true : { publicApproved: { equals: true } },
        create: editor,
        update: editor,
        delete: editor,
      },
      upload: {
        staticDir: path.join(dataDir, "media"),
        mimeTypes: ["image/png", "image/jpeg", "image/webp"],
      },
      fields: [
        { name: "alt", type: "text", required: true },
        { name: "publicApproved", type: "checkbox", defaultValue: false },
      ],
    },
    {
      slug: "chapters",
      admin: { useAsTitle: "title" },
      versions: { drafts: true },
      access: {
        read: (args) => (editor(args) ? true : approvedChapter),
        create: editor,
        update: editor,
        delete: editor,
      },
      fields: [
        { name: "title", type: "text", required: true },
        { name: "slug", type: "text", required: true, unique: true },
        { name: "series", type: "text", required: true },
        { name: "summary", type: "textarea", required: true },
        { name: "editorialApproved", type: "checkbox", defaultValue: false },
        {
          name: "pages",
          type: "array",
          fields: [
            {
              name: "image",
              type: "upload",
              relationTo: "media",
              required: true,
            },
            { name: "caption", type: "textarea" },
          ],
        },
      ],
    },
  ],
  onInit: async (payload) => {
    if (hosted) return;
    const existing = await payload.find({
      collection: "articles",
      limit: 1,
      overrideAccess: true,
    });
    if (existing.totalDocs) return;
    await payload.create({
      collection: "articles",
      overrideAccess: true,
      data: {
        title: "A little more control. A little less complication.",
        slug: "a-little-more-control",
        summary:
          "An introduction to the idea behind Rookstride: make your own VPN, understand the route, and keep your options open.",
        body: "A private server should not require a second career in server administration. Rookstride is being built to guide you through setup and everyday management, with clear steps and useful explanations.\n\nThe same deployment pipeline will be available through different interfaces. Native apps, the browser and future messenger tools are different ways to get the same task done.\n\nThis is sample content stored in the local editor. It demonstrates publishing and reading; it is not a release announcement.",
        category: "project",
        publishedAt: "2026-11-17T12:00:00.000Z",
        sampleContent: true,
        _status: "published",
      },
    });
    await payload.create({
      collection: "articles",
      overrideAccess: true,
      draft: true,
      data: {
        title: "Unpublished local draft",
        slug: "unpublished-local-draft",
        summary: "An editor-only fixture.",
        body: "Drafts must never appear in the public Journal.",
        category: "project",
        publishedAt: "2026-11-17T12:00:00.000Z",
        sampleContent: true,
        _status: "draft",
      },
    });
  },
});
