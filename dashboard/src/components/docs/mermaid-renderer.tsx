'use client';

import { useEffect, useRef, useState } from 'react';

let initialized = false;

interface MermaidRendererProps {
  chart: string;
}

export default function MermaidRenderer({ chart }: MermaidRendererProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const el = containerRef.current;
    if (!el) {
      return;
    }

    const isDark =
      document.documentElement.getAttribute('data-theme') !== 'light';

    (async () => {
      try {
        const { default: mermaid } = await import('mermaid');

        if (!initialized) {
          mermaid.initialize({
            startOnLoad: false,
            theme: isDark ? 'dark' : 'default',
            fontFamily:
              'var(--font-inter), Inter, ui-sans-serif, sans-serif',
            securityLevel: 'strict',
          });
          initialized = true;
        }

        if (cancelled) {
          return;
        }

        const id = `mermaid-${Math.random().toString(36).slice(2, 10)}`;
        const { svg } = await mermaid.render(id, chart);
        if (cancelled) {
          return;
        }
        el.innerHTML = svg;
        setError(null);
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : 'Diagram render failed',
          );
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [chart]);

  if (error) {
    return (
      <pre className="docs-mermaid-error">
        <code>{chart}</code>
      </pre>
    );
  }

  return <div ref={containerRef} className="docs-mermaid" />;
}
