import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DocsShell } from '@/components/docs/docs-shell';
import { DocsSidebar } from '@/components/docs/docs-sidebar';
import { MarkdownProse } from '@/components/docs/markdown-prose';
import {
  extractHeadings,
  getDocsNav,
  getFlattenedDocsPages,
  normalizeDocsMarkdown,
  readDocsMarkdown,
  resolveDocsPage,
} from '@/lib/docs';

interface DocsSlugPageProps {
  params: Promise<{ slug: string[] }>;
}

export async function generateMetadata(
  { params }: DocsSlugPageProps,
): Promise<Metadata> {
  const { slug } = await params;
  const resolved = await resolveDocsPage(slug);
  if (!resolved) {
    return { title: 'Documentation | AgentGate' };
  }

  return {
    title: `${resolved.page.title} | AgentGate Docs`,
    description: `${resolved.section.title} documentation for AgentGate.`,
  };
}

export async function generateStaticParams(): Promise<
  Array<{ slug: string[] }>
> {
  const pages = await getFlattenedDocsPages();
  return pages
    .filter(
      ({ page }) =>
        Boolean(page.path) && !page.external_url && page.slug !== 'api',
    )
    .map(({ page }) => ({ slug: page.slug.split('/') }));
}

export default async function DocsSlugPage(
  { params }: DocsSlugPageProps,
) {
  const { slug } = await params;
  const resolved = await resolveDocsPage(slug);
  if (!resolved || !resolved.page.path) {
    notFound();
  }

  const [nav, flattenedPages, markdown] = await Promise.all([
    getDocsNav(),
    getFlattenedDocsPages(),
    readDocsMarkdown(resolved.page.path),
  ]);
  const pathToSlug = new Map<string, string>(
    flattenedPages
      .filter(({ page }) => Boolean(page.path))
      .map(({ page }) => [page.path as string, page.slug]),
  );
  const normalizedMarkdown = normalizeDocsMarkdown(markdown);
  const headings = extractHeadings(normalizedMarkdown);

  return (
    <DocsShell>
      <main className="docs-page">
        <div className="docs-layout-grid docs-layout-grid--detail">
          <DocsSidebar
            sections={nav.sections}
            currentSlug={resolved.page.slug}
          />

          <section className="docs-surface docs-surface--article">
            <article className="docs-article">
              <header className="docs-pagehead">
                <p className="docs-pagehead__eyebrow">
                  {resolved.section.title}
                </p>
                <h1 className="docs-pagehead__title">
                  {resolved.page.title}
                </h1>
              </header>

              <MarkdownProse
                markdown={normalizedMarkdown}
                sourcePath={resolved.page.path}
                pathToSlug={pathToSlug}
              />
            </article>
          </section>

          {headings.length > 0 && (
            <aside className="docs-outline" aria-label="On this page">
              <p className="docs-outline__title">On This Page</p>
              <nav className="docs-outline__nav">
                {headings.map((heading, idx) => (
                  <a
                    key={`${heading.id}-${heading.level}-${idx}`}
                    href={`#${heading.id}`}
                    className={`docs-outline__link level-${heading.level}`}
                  >
                    {heading.text}
                  </a>
                ))}
              </nav>
            </aside>
          )}
        </div>
      </main>
    </DocsShell>
  );
}
