import Link from 'next/link';

export default function DocsNotFoundPage() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-16 text-center">
      <p className="text-xs uppercase tracking-[0.18em] text-[var(--muted-foreground)]">Documentation</p>
      <h1 className="mt-2 text-3xl font-semibold">Page Not Found</h1>
      <p className="mt-3 text-sm text-[var(--muted-foreground)]">
        The requested documentation page does not exist in the current binder.
      </p>
      <Link
        href="/docs"
        className="mt-6 inline-block rounded-md bg-[var(--primary)] px-4 py-2 text-sm font-semibold text-[var(--primary-foreground)] shadow-sm shadow-[rgba(1,99,57,0.45)] transition hover:brightness-110"
      >
        Return to Docs Home
      </Link>
    </main>
  );
}
