import { Github, Globe } from 'lucide-react';

interface DocsAttributionProps {
  className?: string;
}

export function DocsAttribution({ className }: DocsAttributionProps) {
  return (
    <div className={className}>
      <span className="docs-shell__identity">Erick Aleman</span>
      <span className="docs-shell__sep" aria-hidden="true">
        |
      </span>
      <a
        href="https://github.com/eacognitive"
        target="_blank"
        rel="noreferrer"
        className="docs-shell__external-link"
        aria-label="GitHub profile for Erick Aleman"
      >
        <Github className="docs-shell__external-icon" aria-hidden="true" />
        <span className="docs-shell__external-label">github.com/eacognitive</span>
      </a>
      <span className="docs-shell__sep" aria-hidden="true">
        |
      </span>
      <a
        href="https://www.eacognitive.com"
        target="_blank"
        rel="noreferrer"
        className="docs-shell__external-link"
        aria-label="Website for Erick Aleman"
      >
        <Globe className="docs-shell__external-icon" aria-hidden="true" />
        <span className="docs-shell__external-label">www.eacognitive.com</span>
      </a>
    </div>
  );
}
