import { cache } from 'react';
import docsBundle from '@/generated/docs-bundle.json';

export type DocsClass = 'core' | 'reference' | 'archive' | 'duplicate';

export interface DocsClassificationItem {
  path: string;
  class: DocsClass;
  owner: string;
}

export interface DocsClassification {
  version: number;
  description: string;
  files: DocsClassificationItem[];
}

export interface DocsMigrationEntry {
  old_path: string;
  new_path: string;
  action: string;
  notes: string;
}

export interface DocsMigrationMap {
  version: number;
  description: string;
  entries: DocsMigrationEntry[];
}

export interface DocsNavPage {
  id: string;
  title: string;
  slug: string;
  path?: string;
  external_url?: string;
  status: string;
  aliases: string[];
}

export interface DocsNavSection {
  id: string;
  title: string;
  order: number;
  pages: DocsNavPage[];
}

export interface DocsNav {
  version: number;
  site: {
    title: string;
    base_path: string;
    api_reference_path: string;
  };
  sections: DocsNavSection[];
}

export interface DocsHeading {
  id: string;
  text: string;
  level: number;
}

export interface DocsResolvedPage {
  page: DocsNavPage;
  section: DocsNavSection;
}

interface DocsBundle {
  version: number;
  nav: DocsNav;
  classification: DocsClassification;
  migration: DocsMigrationMap;
  contents: Record<string, string>;
}

const bundle = docsBundle as DocsBundle;
const docsClassByPath = new Map<string, DocsClass>(
  bundle.classification.files.map((entry) => [entry.path, entry.class]),
);
const PUBLIC_DOC_PAGE_IDS = new Set([
  'overview',
  'demo-guide',
  'mcp-server',
  'command-reference',
  'docker-deployment',
  'api-reference',
]);
const HIDDEN_SECTION_IDS = new Set([
  'archive',
  'reports',
  'specs',
  'testing',
  'reference',
]);

function isVisibleDocsPage(section: DocsNavSection, page: DocsNavPage): boolean {
  if (HIDDEN_SECTION_IDS.has(section.id) || page.slug.startsWith('archive/')) {
    return false;
  }
  if (!PUBLIC_DOC_PAGE_IDS.has(page.id)) {
    return false;
  }
  if (page.status.toLowerCase() === 'archived') {
    return false;
  }
  if (page.path && docsClassByPath.get(page.path) === 'archive') {
    return false;
  }
  return true;
}

export const getDocsNav = cache(async (): Promise<DocsNav> => {
  const sections = [...bundle.nav.sections]
    .sort((a, b) => a.order - b.order)
    .filter((section) => !HIDDEN_SECTION_IDS.has(section.id))
    .map((section) => ({
      ...section,
      pages: section.pages.filter((page) => isVisibleDocsPage(section, page)),
    }))
    .filter((section) => section.pages.length > 0);
  return {
    ...bundle.nav,
    sections,
  };
});

export const getDocsClassification = cache(async (): Promise<DocsClassification> => {
  return bundle.classification;
});

export const getDocsMigrationMap = cache(async (): Promise<DocsMigrationMap> => {
  return bundle.migration;
});

export interface DocsTimelineEntry {
  position: number;
  sectionId: string;
  sectionTitle: string;
  page: DocsNavPage;
}

export const getChronologicalDocsEntries = cache(async (): Promise<DocsTimelineEntry[]> => {
  const nav = await getDocsNav();
  let position = 1;
  return nav.sections.flatMap((section) =>
    section.pages.map((page) => ({
      position: position++,
      sectionId: section.id,
      sectionTitle: section.title,
      page,
    })),
  );
});

export async function getFlattenedDocsPages(): Promise<DocsResolvedPage[]> {
  const nav = await getDocsNav();
  return nav.sections.flatMap((section) => section.pages.map((page) => ({ page, section })));
}

export async function resolveDocsPage(slugSegments: string[]): Promise<DocsResolvedPage | null> {
  const slug = slugSegments.join('/');
  const nav = await getDocsNav();

  for (const section of nav.sections) {
    if (slug === section.id && section.pages.length > 0) {
      return { section, page: section.pages[0] };
    }

    for (const page of section.pages) {
      if (page.slug === slug) {
        return { section, page };
      }
    }
  }

  return null;
}

export async function readDocsMarkdown(relativePath: string): Promise<string> {
  const content = bundle.contents[relativePath];
  if (content === undefined) {
    throw new Error(`Unsupported docs path: ${relativePath}`);
  }
  return content;
}

function trimLeadingBlankLines(lines: string[]): string[] {
  let index = 0;
  while (index < lines.length && !lines[index]?.trim()) {
    index += 1;
  }
  return lines.slice(index);
}

function stripLeadingTitle(lines: string[]): string[] {
  const normalized = trimLeadingBlankLines(lines);
  if (!normalized[0]?.match(/^#\s+/)) {
    return normalized;
  }

  return trimLeadingBlankLines(normalized.slice(1));
}

function stripLeadingMetadata(lines: string[]): string[] {
  let remaining = trimLeadingBlankLines(lines);

  while (
    remaining[0]?.startsWith('> ')
    || remaining[0]?.match(/^\*\*(Version|Last Updated|Security Score)\*\*:/)
    || remaining[0] === '**AgentGate Security Architecture**'
  ) {
    remaining = trimLeadingBlankLines(remaining.slice(1));
  }

  if (remaining[0]?.match(/^---+$/)) {
    remaining = trimLeadingBlankLines(remaining.slice(1));
  }

  return remaining;
}

function stripLeadingTableOfContents(lines: string[]): string[] {
  const remaining = trimLeadingBlankLines(lines);
  const tocIndex = remaining.findIndex(
    (line, index) =>
      index < 40 && line.match(/^##\s+(Table of Contents|Contents)$/i),
  );
  if (tocIndex === -1) {
    return remaining;
  }

  let index = tocIndex + 1;
  while (index < remaining.length) {
    const line = remaining[index] ?? '';
    if (line.match(/^##\s+/) && !line.match(/^##\s+(Table of Contents|Contents)$/i)) {
      break;
    }
    index += 1;
  }

  const beforeToc = remaining.slice(0, tocIndex);
  const afterToc = trimLeadingBlankLines(remaining.slice(index));
  return [...beforeToc, ...afterToc];
}

export function normalizeDocsMarkdown(markdown: string): string {
  const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
  const withoutTitle = stripLeadingTitle(lines);
  const withoutMetadata = stripLeadingMetadata(withoutTitle);
  const withoutToc = stripLeadingTableOfContents(withoutMetadata);
  return withoutToc.join('\n').trim();
}

export function slugifyHeading(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
}

export function extractHeadings(markdown: string): DocsHeading[] {
  const lines = markdown.split('\n');
  const headings: DocsHeading[] = [];

  for (const line of lines) {
    const match = line.match(/^(#{2,3})\s+(.+)$/);
    if (!match) {
      continue;
    }

    const level = match[1].length;
    const rawText = match[2].replace(/`/g, '').trim();
    const text = rawText.replace(/\[(.*?)\]\([^)]*\)/g, '$1');
    headings.push({
      id: slugifyHeading(text),
      text,
      level,
    });
  }

  return headings;
}
