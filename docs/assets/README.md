# Asset Organization

This repository uses two different README surfaces:

- `README.md` is the GitHub-facing document and can reference repo-relative images.
- `README_PYPI.md` is the package description used by PyPI and should not depend on repo-relative
  images.

## Folder Layout

- `assets/screenshots/`: curated screenshots used by the root repository README.
- `docs/assets/`: diagrams and illustrations used by docs pages.
- `docs/assets/raw-screenshots/`: raw capture exports and candidate screenshots before curation.

## Naming Rules

- Use lowercase kebab-case names such as `homepage-hero.png` or `pii-audit-log.png`.
- Keep curated public-facing assets descriptive and stable.
- Leave raw captures in `docs/assets/raw-screenshots/` until they are promoted into a curated
  asset.

## PyPI Rule

Do not point PyPI at a README that depends on repo-relative images. PyPI should use
`README_PYPI.md` so the package page remains clean even before the public repository is live.

## Screenshot Checklist

1. Use real product screens, not placeholders.
2. Remove sensitive data before committing assets.
3. Prefer dark-theme captures for UI screenshots.
4. Promote only the strongest screenshots into `assets/screenshots/`.
