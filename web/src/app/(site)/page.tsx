import { getLanguage, getMessages } from "@/i18n/messages";
import { RichMessage } from "@/i18n/rich-message";
import Link from "next/link";
import { Icon } from "@/components/icons";
import { RookSetupIllustration } from "@/components/rook-character";
import { RookJourney } from "@/components/route-preview";
import { SetupOptions } from "@/components/setup-options";
import styles from "@/components/site-guide.module.css";
import { articleCategory, articles, featuredChapter } from "@/lib/content";
import { publicPageMetadata } from "@/lib/site-discovery";

const { home: copy, connect, demo } = getMessages("site");
const setup = getMessages("route").guide.setup;
const guideLanguage = getLanguage("route");
const setupSteps = [setup.rent, setup.details, setup.connect, setup.invite];
const stepNumber = new Intl.NumberFormat(guideLanguage.tag);

export const dynamic = "force-dynamic";

export function generateMetadata() {
  return {
    ...publicPageMetadata(
      "/",
      copy.metaTitle,
      copy.metaDescription,
      "/brand/rook-bridge-team.webp",
    ),
    title: { absolute: copy.metaTitle },
  };
}

export default async function Home() {
  const [[latest], story] = await Promise.all([articles(), featuredChapter()]);
  return (
    <main>
      <section className={styles.hero} aria-labelledby="home-title">
        <div className={`page-width ${styles.heroGrid}`}>
          <div className={styles.introduction}>
            <h1 id="home-title">
              <RichMessage
                text={copy.headline}
                values={{ ownership: <span>{copy.accent}</span> }}
              />
            </h1>
            <p className={styles.lead}>{copy.lead}</p>
            <a className="button primary" href="#setup-options">
              {copy.start} <Icon name="arrow" />
            </a>
            <p className={styles.cost}>{copy.cost}</p>
          </div>
          <RookJourney />
        </div>
      </section>
      <section
        className={`page-width ${styles.setupOptions}`}
        id="setup-options"
        aria-labelledby="setup-options-title"
      >
        <h2 id="setup-options-title">{copy.options}</h2>
        <SetupOptions />
        <div className={styles.setupSupport}>
          <Link className="button secondary" href="/manage#practice">
            {demo.action} <Icon name="arrow" />
          </Link>
          <div className={styles.setupHelp}>
            <Link className="text-link" href="/connect">
              {connect.navLabel}
            </Link>
            <Link className="text-link" href="/self-hosted-vpn">
              {copy.technology}
            </Link>
          </div>
        </div>
      </section>
      <section
        className={`page-width ${styles.setupStrip}`}
        aria-labelledby="setup-guide-title"
        lang={guideLanguage.tag}
        dir={guideLanguage.dir}
      >
        <div className={styles.setupIntro}>
          <h2 id="setup-guide-title">{setup.title}</h2>
          <div className={styles.setupPortrait}>
            <RookSetupIllustration />
          </div>
        </div>
        <ol role="list" className={styles.setupSteps}>
          {setupSteps.map((step, index) => (
            <li key={index}>
              <span aria-hidden="true" className={styles.waypoint}>
                {stepNumber.format(index + 1)}
              </span>
              <div>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>
      <div className={`page-width ${styles.afterSetup}`}>
        <section
          className={styles.ownership}
          aria-labelledby="ownership-heading"
        >
          <div>
            <h2 id="ownership-heading">{copy.ownerTitle}</h2>
            <p>{copy.ownerLead}</p>
          </div>
          <dl className={styles.controls}>
            <div>
              <dt>
                <Icon name="guests" />
                <span>{copy.accessTitle}</span>
              </dt>
              <dd>{copy.accessBody}</dd>
            </div>
            <div>
              <dt>
                <Icon name="traffic" />
                <span>{copy.usageTitle}</span>
              </dt>
              <dd>{copy.usageBody}</dd>
            </div>
            <div>
              <dt>
                <Icon name="shield" />
                <span>{copy.filterTitle}</span>
              </dt>
              <dd>{copy.filterBody}</dd>
            </div>
          </dl>
        </section>
        <figure className={styles.bridgeIllustration}>
          <img
            src="/brand/rook-bridge-team.webp"
            alt={copy.bridgeAlt}
            width="1000"
            height="1000"
            loading="lazy"
          />
          <figcaption>
            <Link href="/comics#rook-origin">{copy.meetRook}</Link>
          </figcaption>
        </figure>
      </div>
      {story && (
        <section
          className={`page-width ${styles.storyPreview}`}
          aria-labelledby="story-title"
        >
          <img
            loading="lazy"
            src={story.pages[0].src}
            alt={story.pages[0].alt}
          />
          <div>
            <p>{getMessages("site").comics.title}</p>
            <h2 id="story-title">{story.title}</h2>
            <p>{story.summary}</p>
            <Link className="text-link" href={story.href}>
              {getMessages("site").comics.read} <Icon name="arrow" />
            </Link>
          </div>
        </section>
      )}
      {latest && (
        <section
          className={`page-width ${styles.journal}`}
          aria-labelledby="latest-journal-title"
        >
          <div>
            <h2 id="latest-journal-title">{copy.journalTitle}</h2>
            <Link className="text-link" href="/journal">
              {copy.articles} <Icon name="arrow" />
            </Link>
          </div>
          <Link
            className={styles.featuredPost}
            href={`/journal/${latest.slug}`}
          >
            <div>
              <p className={styles.byline}>{articleCategory(latest)}</p>
              <h3>{latest.title}</h3>
              <p>{latest.summary}</p>
            </div>
            <Icon name="arrow" />
          </Link>
        </section>
      )}
    </main>
  );
}
