import type { Metadata } from 'next';
import { DocsShell } from '@/components/docs/docs-shell';
import { ScalarApiReference } from '@/components/docs/scalar-api-reference';

export const metadata: Metadata = {
  title: 'API Reference | AgentGate',
  description:
    'Interactive API reference rendered from the live OpenAPI document.',
};

export default function ApiReferencePage() {
  return (
    <DocsShell>
      <ScalarApiReference specUrl="/api/reference/openapi.json" />
    </DocsShell>
  );
}
