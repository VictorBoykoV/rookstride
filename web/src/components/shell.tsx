import { getMessages } from "@/i18n/messages";
import Link from "next/link";
import { Icon } from "./icons";
import styles from "./site-guide.module.css";

const { shell: copy, connect } = getMessages("site");

export function Header() {
  return (
    <header className={styles.masthead}>
      <div className={`page-width ${styles.mastheadInner}`}>
        <Link className={styles.wordmark} href="/" aria-label={copy.homeLabel}>
          <img src="/brand/rook.svg" alt="" width="36" height="36" />
          {copy.wordmark}
        </Link>
        <nav className={styles.menu} aria-label={copy.mainNav}>
          <Link href="/#how-it-works">{copy.how}</Link>
          <Link href="/connect">{connect.navLabel}</Link>
          <Link href="/journal">{copy.journal}</Link>
          <Link href="/comics">{copy.comics}</Link>
          <Link href="/providers">{copy.providers}</Link>
        </nav>
        <Link href="/start" className={styles.startLink}>
          {copy.start} <Icon name="arrow" />
        </Link>
      </div>
    </header>
  );
}

export function Footer() {
  return (
    <footer className={styles.footer}>
      <div className={`page-width ${styles.footerInner}`}>
        <div>
          <Link href="/" className={styles.wordmark}>
            <img src="/brand/rook.svg" width="30" height="30" alt="" />
            {copy.wordmark}
          </Link>
          <p>{copy.motto}</p>
        </div>
        <nav aria-label={copy.footerNav} className={styles.footerNav}>
          <div>
            <Link href="/manage">{copy.browser}</Link>
            <Link href="/downloads">{copy.android}</Link>
            <Link href="/connect">{connect.navLabel}</Link>
            <Link href="/agents">{copy.agents}</Link>
          </div>
          <div>
            <Link href="/providers">{copy.partner}</Link>
            <a
              href="https://github.com/VictorBoykoV/rookstride"
              target="_blank"
              rel="noreferrer"
            >
              {copy.source} <Icon name="external" />
            </a>
          </div>
        </nav>
      </div>
    </footer>
  );
}
