'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  useEffect,
  useRef,
  type ReactNode,
} from 'react';
import { DocsAttribution } from '@/components/docs/docs-attribution';

interface DocsShellProps {
  children: ReactNode;
}

export function DocsShell({ children }: DocsShellProps) {
  const pathname = usePathname();
  const frameRef = useRef<HTMLDivElement | null>(null);
  const headerRef = useRef<HTMLElement | null>(null);
  const isApi = pathname === '/docs/api-reference'
    || pathname.startsWith('/docs/api-reference/');

  useEffect(() => {
    const frame = frameRef.current;
    const header = headerRef.current;
    if (!frame || !header) {
      return;
    }

    const updateHeaderHeight = () => {
      frame.style.setProperty(
        '--docs-shell-topbar-height',
        `${header.offsetHeight}px`,
      );
    };

    updateHeaderHeight();
    const observer = new ResizeObserver(updateHeaderHeight);
    observer.observe(header);
    window.addEventListener('resize', updateHeaderHeight);

    return () => {
      observer.disconnect();
      window.removeEventListener('resize', updateHeaderHeight);
    };
  }, [pathname]);

  return (
    <div className="docs-shell">
      <div ref={frameRef} className="docs-shell__frame">
        <header ref={headerRef} className="docs-shell__topbar">
          <Link href="/" className="docs-shell__logo">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src="/logos/logo_dark_background.svg"
              alt="AgentGate"
              className="docs-shell__logo-img logo-dark"
            />
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src="/logos/logo_white_background.svg"
              alt="AgentGate"
              className="docs-shell__logo-img logo-light"
            />
          </Link>
          <nav className="docs-shell__nav">
            <Link
              href="/docs"
              className={
                'docs-shell__nav-link'
                + (isApi ? '' : ' is-active')
              }
            >
              Guide
            </Link>
            <Link
              href="/docs/api-reference"
              className={
                'docs-shell__nav-link'
                + (isApi ? ' is-active' : '')
              }
            >
              Reference
            </Link>
          </nav>
          <DocsAttribution className="docs-shell__meta" />
        </header>
        <div className="docs-shell__content">{children}</div>
      </div>
    </div>
  );
}
