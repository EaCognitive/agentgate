import type { AnyApiReferenceConfiguration } from '@scalar/api-reference-react';

type DocsThemeMode = 'dark' | 'light';

export const SCALAR_CUSTOM_CSS = `
.scalar-api-reference {
  --scalar-font: var(--font-inter), Inter, sans-serif;
  --scalar-font-code: var(--font-mono), 'JetBrains Mono', monospace;
  --scalar-background-1: var(--s-bg-1);
  --scalar-background-2: var(--s-bg-2);
  --scalar-background-3: var(--s-bg-3);
  --scalar-color-1: var(--s-c-1);
  --scalar-color-2: var(--s-c-2);
  --scalar-color-3: var(--s-c-3);
  --scalar-color-accent: var(--s-accent);
  --scalar-border-color: var(--s-border);
  --scalar-sidebar-width: 280px;
  --scalar-content-max-width: 1440px;
  min-height: 100%;
  background: var(--s-bg-1);
}

.scalar-api-reference .t-doc__sidebar {
  border-right: 1px solid var(--s-border);
}

.scalar-api-reference .references-classic-header,
.scalar-api-reference .t-doc__header,
.scalar-api-reference .darklight-reference,
.scalar-api-reference .scalar-footer {
  display: none !important;
}

.scalar-api-reference .reference-layout,
.scalar-api-reference .references-layout {
  min-height: 100%;
}

@media (max-width: 1000px) {
  .scalar-api-reference {
    --scalar-sidebar-width: 100%;
  }
}
`;

export function buildScalarConfiguration(
  specUrl: string,
  themeMode: DocsThemeMode,
): AnyApiReferenceConfiguration {
  return {
    _integration: 'react',
    url: specUrl,
    theme: 'none',
    layout: 'modern',
    forceDarkModeState: themeMode,
    withDefaultFonts: false,
    showDeveloperTools: 'never',
    hideDarkModeToggle: true,
    hideClientButton: true,
    documentDownloadType: 'none',
    defaultOpenAllTags: false,
    hideModels: false,
    persistAuth: true,
    customCss: SCALAR_CUSTOM_CSS,
    metaData: {
      title: 'AgentGate API Reference',
      description: 'Enterprise-grade AI agent governance middleware',
    },
    authentication: {
      preferredSecurityScheme: 'bearerAuth',
    },
  };
}
