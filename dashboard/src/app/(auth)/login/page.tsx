'use client';

import { useState, FormEvent, Suspense, useEffect } from 'react';
import { signIn } from 'next-auth/react';
import Image from 'next/image';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { FlickeringGrid } from '@/components/ui/flickering-grid';
import { Eye, EyeOff, Sun, Moon } from 'lucide-react';
import { useTheme } from '@/lib/theme';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get('callbackUrl') || '/';
  const registered = searchParams.get('registered');
  const error = searchParams.get('error');
  const providerToken = searchParams.get('provider_token');
  const providerHint = searchParams.get('provider_hint') || searchParams.get('provider');
  const { theme, toggleTheme } = useTheme();
  const logoSrc = '/logos/logo_dark_background.svg';
  const iconSrc = theme === 'light'
    ? '/logos/Square_icon_white_background.svg'
    : '/logos/Square_icon_black_background.svg';

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [setupChecking, setSetupChecking] = useState(true);
  const [providerMode, setProviderMode] = useState('local');
  const [localPasswordAuthAllowed, setLocalPasswordAuthAllowed] = useState(true);
  const [providerLoading, setProviderLoading] = useState(true);
  const ssoSignInUrl =
    process.env.NEXT_PUBLIC_SSO_SIGNIN_URL
    || process.env.NEXT_PUBLIC_DESCOPE_SIGNIN_URL
    || '';
  const ssoProviderName =
    process.env.NEXT_PUBLIC_SSO_PROVIDER_NAME
    || (providerMode === 'descope' ? 'Descope' : 'SSO');

  useEffect(() => {
    let mounted = true;

    const checkSetupRequired = async () => {
      try {
        const response = await fetch('/api/setup/status', { cache: 'no-store' });
        const data = await response.json().catch(() => ({}));
        if (mounted && response.ok && data.setup_required) {
          router.replace('/setup');
          return;
        }
      } catch {
        // Keep login form available if setup status endpoint is unreachable.
      } finally {
        if (mounted) {
          setSetupChecking(false);
        }
      }
    };

    void checkSetupRequired();
    return () => {
      mounted = false;
    };
  }, [router]);

  useEffect(() => {
    let mounted = true;
    const loadProviderMode = async () => {
      try {
        const res = await fetch('/api/identity/providers', { cache: 'no-store' });
        const data = await res.json().catch(() => ({}));
        if (mounted && res.ok) {
          setProviderMode(String(data.mode || 'local'));
          setLocalPasswordAuthAllowed(Boolean(data.local_password_auth_allowed));
        }
      } catch {
        if (mounted) {
          setProviderMode('local');
          setLocalPasswordAuthAllowed(true);
        }
      } finally {
        if (mounted) {
          setProviderLoading(false);
        }
      }
    };

    void loadProviderMode();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!providerToken) return;
    let mounted = true;

    const exchangeProviderToken = async () => {
      setIsLoading(true);
      setSubmitError(null);
      try {
        const result = await signIn('credentials', {
          providerToken,
          providerHint: providerHint || undefined,
          redirect: false,
        });
        if (!mounted) return;
        if (result?.error) {
          setSubmitError(result.error);
          return;
        }
        if (result?.ok) {
          router.push(callbackUrl);
          router.refresh();
        }
      } catch {
        if (mounted) {
          setSubmitError('Provider sign-in failed');
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    };

    void exchangeProviderToken();
    return () => {
      mounted = false;
    };
  }, [providerToken, providerHint, callbackUrl, router]);

  if (setupChecking) {
    return <div className="flex min-h-screen items-center justify-center">Loading...</div>;
  }
  if (providerLoading) {
    return <div className="flex min-h-screen items-center justify-center">Loading...</div>;
  }

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!localPasswordAuthAllowed) {
      setSubmitError(`Password login is disabled. Use the ${ssoProviderName} sign-in option.`);
      return;
    }
    setIsLoading(true);
    setSubmitError(null);

    try {
      const result = await signIn('credentials', {
        email,
        password,
        redirect: false,
      });

      if (result?.error) {
        setSubmitError('Invalid email or password');
      } else if (result?.ok) {
        router.push(callbackUrl);
        router.refresh();
      }
    } catch {
      setSubmitError('An unexpected error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen isolate">
      {/* Left Side - Branding */}
      <div className="relative z-0 hidden lg:flex lg:w-1/2 lg:items-center lg:justify-center bg-[#0a0a0a] overflow-hidden">
        <FlickeringGrid
          className="absolute inset-0 z-0"
          squareSize={4}
          gridGap={6}
          color="#016339"
          maxOpacity={0.6}
          flickerChance={0.15}
        />
        {/* Gradient overlays for text readability */}
        <div className="absolute inset-0 z-[1] bg-gradient-to-br from-[#0a0a0a]/70 via-[#0a0a0a]/40 to-transparent pointer-events-none" />
        <div className="absolute inset-0 z-[1] bg-gradient-to-t from-[#0a0a0a]/90 via-transparent to-[#0a0a0a]/60 pointer-events-none" />

        {/* Centered Content */}
        <div className="relative z-10 text-center px-12 max-w-2xl">
          {/* Logo */}
          <div className="mb-6 flex flex-col items-center gap-3">
            <div className="drop-shadow-[0_35px_80px_rgba(8,192,193,0.4)]">
              <Image
                src={logoSrc}
                alt="AgentGate logo"
                width={336}
                height={336}
                priority
                className="w-84 h-auto"
              />
            </div>
            <div className="flex flex-col items-center gap-0.5 text-white mt-1">
              <span className="text-base uppercase tracking-[0.32em] text-[#8ae6c3] font-medium">SECURE AI GATEWAY</span>
            </div>
          </div>

          {/* Tagline */}
          <h1 className="text-3xl font-semibold text-white mb-4 leading-tight">
            Formally Verified Policy Enforcement
          </h1>
          <p className="text-lg text-gray-300 leading-relaxed max-w-xl mx-auto">
            Every agent tool call is evaluated against declarative policy sets,
            verified with Z3 proofs, and recorded with signed decision certificates.
          </p>
        </div>
      </div>

      {/* Right Side - Form */}
      <div className="relative z-20 flex w-full flex-col lg:w-1/2 bg-background pointer-events-auto">
        {/* Signature - Bottom Right */}
        <div className="absolute bottom-6 right-8 z-10 text-right opacity-40 hover:opacity-70 transition-opacity">
          <div className="flex flex-col gap-1.5 text-xs text-muted-foreground">
            <p className="font-normal">Erick Aleman | AI Architect | AI Engineer</p>
            <div className="flex items-center justify-end gap-3">
              <a
                href="mailto:Erick@EACognitive.com"
                className="hover:text-[#8ae6c3] transition-colors"
              >
                Erick@EACognitive.com
              </a>
              <a
                href="https://github.com/EaCognitive"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-[#8ae6c3] transition-colors"
                aria-label="GitHub"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8"/>
                </svg>
              </a>
            </div>
          </div>
        </div>

        {/* Theme Toggle */}
        <div className="absolute top-6 right-6 z-30">
          <button
            onClick={toggleTheme}
            className="rounded-lg p-2 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
          </button>
        </div>

        {/* Form Container - Centered */}
        <div className="flex flex-1 items-center justify-center px-8">
          <div className="w-full max-w-sm">
            {/* Mobile Branding */}
            <div className="mb-8 flex items-center gap-3 lg:hidden">
              <Image
                src={iconSrc}
                alt="AgentGate emblem"
                width={48}
                height={48}
                className="rounded-xl shadow-[0_16px_42px_-28px_rgba(8,192,193,0.9)]"
              />
              <div className="flex flex-col">
                <span className="text-base font-semibold text-foreground">AgentGate</span>
                <span className="text-xs text-muted-foreground">Agent policy enforcement</span>
              </div>
            </div>
            {/* Header */}
            <div className="mb-8">
              <h2 className="text-2xl font-semibold text-foreground">Welcome back</h2>
              <p className="mt-2 text-sm text-muted-foreground">
                Sign in to your account to continue
              </p>
            </div>

            {/* Success Message */}
            {registered && (
              <div className="mb-6 rounded-lg border border-[#016339]/30 bg-[#016339]/10 p-3">
                <p className="text-sm text-[#016339]">Account created. Sign in to continue.</p>
              </div>
            )}

            {/* Error Message - only show user-facing errors */}
            {(submitError || error === 'CredentialsSignin') && (
              <div className="mb-6 rounded-lg border border-destructive/30 bg-destructive/10 p-3">
                <p className="text-sm text-destructive">
                  {submitError || 'Invalid email or password'}
                </p>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              {!localPasswordAuthAllowed && (
                <div className="rounded-lg border border-[#016339]/30 bg-[#016339]/10 p-3 text-sm text-[#016339]">
                  Local password login is disabled. Continue with {ssoProviderName} below.
                </div>
              )}
              <div>
                <label className="mb-2 block text-sm font-medium text-foreground">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  disabled={isLoading || !localPasswordAuthAllowed}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder-muted-foreground transition-colors focus:border-[#016339] focus:outline-none focus:ring-1 focus:ring-[#016339] disabled:opacity-50"
                />
              </div>

              <div>
                <label className="mb-2 block text-sm font-medium text-foreground">Password</label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    required
                    disabled={isLoading || !localPasswordAuthAllowed}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 pr-10 text-sm text-foreground placeholder-muted-foreground transition-colors focus:border-[#016339] focus:outline-none focus:ring-1 focus:ring-[#016339] disabled:opacity-50"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading || !localPasswordAuthAllowed}
                className="w-full rounded-md bg-[#016339] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#016339]/90 disabled:opacity-50"
              >
                {isLoading ? 'Signing in...' : 'Sign in'}
              </button>
            </form>

            {providerMode !== 'local' && (
              <>
                <div className="my-6 flex items-center gap-4">
                  <div className="h-px flex-1 bg-border"></div>
                  <span className="text-xs text-muted-foreground">or continue with</span>
                  <div className="h-px flex-1 bg-border"></div>
                </div>
                <a
                  href={ssoSignInUrl || '#'}
                  className="flex items-center justify-center gap-2 rounded-md border border-border bg-background px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-muted disabled:opacity-50"
                  aria-disabled={!ssoSignInUrl}
                >
                  Continue with {ssoProviderName}
                </a>
                {!ssoSignInUrl && (
                  <p className="mt-2 text-xs text-muted-foreground">
                    Configure <code>NEXT_PUBLIC_SSO_SIGNIN_URL</code> to enable redirect sign-in.
                  </p>
                )}
              </>
            )}

            {/* Sign Up Link */}
            <p className="mt-8 text-center text-sm text-muted-foreground">
              Don&apos;t have an account?{' '}
              <Link href="/signup" className="font-medium text-[#016339] hover:underline">
                Sign up
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center">Loading...</div>}>
      <LoginForm />
    </Suspense>
  );
}
