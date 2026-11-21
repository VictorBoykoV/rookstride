import { getMessages } from "@/i18n/messages";
import Link from "next/link";

const copy = getMessages("site").missing;

export default function NotFound() {
  return (
    <main className="page-width inner-page">
      <div className="page-intro">
        <p className="eyebrow">{copy.eyebrow}</p>
        <h1>{copy.title}</h1>
        <p>{copy.description}</p>
        <Link className="button primary" href="/">
          {copy.home}
        </Link>
      </div>
    </main>
  );
}
