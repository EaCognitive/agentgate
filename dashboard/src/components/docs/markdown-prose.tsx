import path from 'node:path';
import Link from 'next/link';
import { isValidElement, type ReactNode } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { slugifyHeading } from '@/lib/docs';
import { MermaidBlock } from '@/components/docs/mermaid-block';

interface MarkdownProseProps {
  markdown: string;
  sourcePath: string;
  pathToSlug: Map<string, string>;
}

const DASHBOARD_API_REFERENCE_PATH = '/docs/api-reference';
const API_REFERENCE_SOURCE_PATH = 'docs/overview.md';

function normalizeRepoPath(filePath: string): string {
  return filePath.replace(/\\/g, '/');
}

function resolveRootHref(rawPathPart: string): string {
  const normalized = rawPathPart.length > 1 && rawPathPart.endsWith('/')
    ? rawPathPart.slice(0, -1)
    : rawPathPart;

  if (normalized === '/api' || normalized === '/api/reference') {
    return DASHBOARD_API_REFERENCE_PATH;
  }

  return normalized;
}

function resolveDocHref(
  href: string,
  sourcePath: string,
  pathToSlug: Map<string, string>,
): string | null {
  const [rawPathPart, hashPart] = href.split('#');
  const hash = hashPart ? `#${hashPart}` : '';

  if (!rawPathPart) {
    return hash || null;
  }

  if (/^(https?:|mailto:|tel:)/i.test(rawPathPart)) {
    return href;
  }

  if (rawPathPart.startsWith('/')) {
    return `${resolveRootHref(rawPathPart)}${hash}`;
  }

  const baseDir = path.posix.dirname(sourcePath);
  const resolved = normalizeRepoPath(path.posix.normalize(path.posix.join(baseDir, rawPathPart)));

  const candidates = [resolved];
  if (!resolved.endsWith('.md')) {
    candidates.push(`${resolved}.md`);
  }

  for (const candidate of candidates) {
    if (candidate === API_REFERENCE_SOURCE_PATH && hash === '#api-reference') {
      return DASHBOARD_API_REFERENCE_PATH;
    }

    const slug = pathToSlug.get(candidate);
    if (slug) {
      return `/docs/${slug}${hash}`;
    }
  }

  return null;
}

function flattenNodeText(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === 'boolean') {
    return '';
  }
  if (typeof node === 'string' || typeof node === 'number') {
    return String(node);
  }
  if (Array.isArray(node)) {
    return node.map(flattenNodeText).join('');
  }
  if (isValidElement<{ children?: ReactNode }>(node)) {
    return flattenNodeText(node.props.children);
  }
  return '';
}

function headingId(children: ReactNode): string {
  return slugifyHeading(flattenNodeText(children).trim());
}

export function MarkdownProse({ markdown, sourcePath, pathToSlug }: MarkdownProseProps) {
  return (
    <div className="docs-markdown">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => {
            return <h1 id={headingId(children)}>{children}</h1>;
          },
          h2: ({ children }) => {
            return <h2 id={headingId(children)}>{children}</h2>;
          },
          h3: ({ children }) => {
            return <h3 id={headingId(children)}>{children}</h3>;
          },
          h4: ({ children }) => {
            return <h4 id={headingId(children)}>{children}</h4>;
          },
          pre: ({ children }) => {
            // If the child is a mermaid block (rendered by the code
            // override below), pass it through unwrapped so MermaidBlock
            // is not nested inside <pre>.
            if (
              isValidElement<{ className?: string; children?: ReactNode }>(
                children,
              )
              && children.props.className === '__mermaid'
            ) {
              return <>{children.props.children}</>;
            }
            return <pre>{children}</pre>;
          },
          code: ({ className, children }) => {
            const lang = className?.replace('language-', '');
            if (lang === 'mermaid') {
              const chart = flattenNodeText(children).trim();
              return (
                <span className="__mermaid">
                  <MermaidBlock chart={chart} />
                </span>
              );
            }
            return <code className={className}>{children}</code>;
          },
          a: ({ href, children }) => {
            if (!href) {
              return <span>{children}</span>;
            }

            const resolved = resolveDocHref(href, sourcePath, pathToSlug);
            if (!resolved) {
              return <span>{children}</span>;
            }

            if (/^(https?:|mailto:|tel:)/i.test(resolved)) {
              return (
                <a href={resolved} target="_blank" rel="noreferrer noopener">
                  {children}
                </a>
              );
            }

            if (resolved.startsWith('#')) {
              return <a href={resolved}>{children}</a>;
            }

            return <Link href={resolved}>{children}</Link>;
          },
        }}
      >
        {markdown}
      </ReactMarkdown>
    </div>
  );
}
