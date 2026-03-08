'use client';

import dynamic from 'next/dynamic';

const MermaidRenderer = dynamic(
  () => import('@/components/docs/mermaid-renderer'),
  { ssr: false },
);

interface MermaidBlockProps {
  chart: string;
}

export function MermaidBlock({ chart }: MermaidBlockProps) {
  return <MermaidRenderer chart={chart} />;
}
