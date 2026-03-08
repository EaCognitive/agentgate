import Link from 'next/link';
import type { Metadata } from 'next';
import { DocsShell } from '@/components/docs/docs-shell';
import { DocsSidebar } from '@/components/docs/docs-sidebar';
import { getDocsNav } from '@/lib/docs';

export const metadata: Metadata = {
  title: 'Documentation | AgentGate',
  description: 'Curated product guide and live API reference for AgentGate.',
};

const HOME_ACTIONS = [
  {
    href: '/docs/getting-started/overview',
    label: 'Start Here',
    variant: 'primary',
  },
  {
    href: '/docs/api-reference',
    label: 'Open API Reference',
    variant: 'secondary',
  },
] as const;

export default async function DocsHomePage() {
  const nav = await getDocsNav();

  return (
    <DocsShell>
      <main className="docs-page">
        <div className="docs-layout-grid">
          <DocsSidebar sections={nav.sections} />

          <section className="docs-surface docs-surface--article">
            <article className="docs-article docs-article--home">
              <header className="docs-pagehead">
                <p className="docs-pagehead__eyebrow">Guide</p>
                <h1 className="docs-pagehead__title">AgentGate Guide</h1>
                <p className="docs-pagehead__lead">
                  A focused product guide for the local demo flow, the MCP
                  surface, operations commands, and the live Scalar reference.
                </p>
                <div className="docs-home__actions">
                  {HOME_ACTIONS.map((action) => (
                    <Link
                      key={action.href}
                      href={action.href}
                      className={
                        action.variant === 'primary'
                          ? 'docs-button-primary'
                          : 'docs-button-secondary'
                      }
                    >
                      {action.label}
                    </Link>
                  ))}
                </div>
              </header>

              <div className="docs-home__sections">
                {nav.sections.map((section) => (
                  <section
                    key={section.id}
                    className="docs-home__section"
                  >
                    <h2 className="docs-home__section-title">
                      {section.title}
                    </h2>
                    <ul className="docs-home__list">
                      {section.pages.map((page) => {
                        const href =
                          page.external_url
                            ?? `/docs/${page.slug}`;

                        if (
                          page.external_url
                          && /^https?:\/\//.test(page.external_url)
                        ) {
                          return (
                            <li key={page.id}>
                              <a
                                href={href}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="docs-home__link"
                              >
                                <span>{page.title}</span>
                                <span className="docs-home__link-note">
                                  External
                                </span>
                              </a>
                            </li>
                          );
                        }

                        return (
                          <li key={page.id}>
                            <Link
                              href={href}
                              className="docs-home__link"
                            >
                              <span>{page.title}</span>
                              <span className="docs-home__link-note">
                                Open
                              </span>
                            </Link>
                          </li>
                        );
                      })}
                    </ul>
                  </section>
                ))}
              </div>
            </article>
          </section>
        </div>
      </main>
    </DocsShell>
  );
}
