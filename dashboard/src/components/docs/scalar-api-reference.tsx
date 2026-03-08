'use client';

import dynamic from 'next/dynamic';
import { useEffect, useMemo, useState } from 'react';
import { buildScalarConfiguration } from '@/components/docs/scalar-theme';

interface ScalarApiReferenceProps {
  specUrl: string;
}

const ApiReferenceReact = dynamic(
  async () => {
    const mod = await import('@scalar/api-reference-react');
    return mod.ApiReferenceReact;
  },
  {
    ssr: false,
    loading: () => (
      <div className="docs-scalar-loading">
        Loading API reference...
      </div>
    ),
  },
);

function resolveThemeMode(): 'dark' | 'light' {
  if (typeof document === 'undefined') {
    return 'dark';
  }

  return document.documentElement.dataset.theme === 'light'
    ? 'light'
    : 'dark';
}

export function ScalarApiReference({ specUrl }: ScalarApiReferenceProps) {
  const [themeMode, setThemeMode] = useState<'dark' | 'light'>('dark');
  const configuration = useMemo(
    () => buildScalarConfiguration(specUrl, themeMode),
    [specUrl, themeMode],
  );

  useEffect(() => {
    const root = document.documentElement;
    const updateThemeMode = () => {
      setThemeMode(resolveThemeMode());
    };

    updateThemeMode();
    const observer = new MutationObserver(updateThemeMode);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });

    return () => {
      observer.disconnect();
    };
  }, []);

  return (
    <div className="docs-scalar-native">
      <ApiReferenceReact configuration={configuration} />
    </div>
  );
}
