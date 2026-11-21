import { getLanguage, getMessages } from "@/i18n/messages";
import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Header, Footer } from "@/components/shell";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./styles.css";

const copy = getMessages("site").layout;

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: {
    default: copy.pageTitle,
    template: "%s – Rookstride",
  },
  icons: { icon: { url: "/brand/rook.svg", type: "image/svg+xml" } },
  description: copy.description,
  robots: { index: false, follow: false },
};

export default function Layout({ children }: { children: ReactNode }) {
  const language = getLanguage("site");
  return (
    <html lang={language.tag} dir={language.dir} data-scroll-behavior="smooth">
      <body className={`${GeistSans.variable} ${GeistMono.variable}`}>
        <a className="skip-link" href="#main">
          {copy.skip}
        </a>
        <Header />
        <div id="main" tabIndex={-1}>
          {children}
        </div>
        <Footer />
      </body>
    </html>
  );
}
