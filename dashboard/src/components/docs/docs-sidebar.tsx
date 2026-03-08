import Link from 'next/link';
import type { DocsNavSection } from '@/lib/docs';

interface DocsSidebarProps {
  sections: DocsNavSection[];
  currentSlug?: string;
}

export function DocsSidebar(
  { sections, currentSlug }: DocsSidebarProps,
) {
  return (
    <aside
      className="docs-sidebar"
      aria-label="Documentation Sidebar"
    >
      <nav
        aria-label="Documentation navigation"
        className="docs-sidebar__nav"
      >
        {sections.map((section) => (
          <section
            key={section.id}
            className="docs-sidebar__section"
          >
            <h3 className="docs-sidebar__section-title">
              {section.title}
            </h3>
            <ul className="docs-sidebar__list">
              {section.pages.map((page) => {
                const href =
                  page.external_url ?? `/docs/${page.slug}`;
                const isActive = currentSlug === page.slug;
                const className =
                  `docs-sidebar__link${isActive ? ' is-active' : ''}`;

                if (
                  page.external_url
                  && /^https?:\/\//.test(page.external_url)
                ) {
                  return (
                    <li key={page.id}>
                      <a
                        href={page.external_url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className={className}
                      >
                        {page.title}
                      </a>
                    </li>
                  );
                }

                return (
                  <li key={page.id}>
                    <Link href={href} className={className}>
                      {page.title}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </nav>
    </aside>
  );
}
