import type { ReactNode } from 'react';
import '@scalar/api-reference-react/style.css';
import './docs.css';

export default function DocsLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
