'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';

type SetupStatus = {
  setup_required: boolean;
  user_count: number;
  message: string;
};

type SetupResponse = {
  success: boolean;
  email: string;
  api_key?: string;
  api_key_prefix?: string;
};

type AuthProfile = 'jwt' | 'api_key' | 'azure_confidential';

const AUTH_PROFILE_OPTIONS: Array<{ id: AuthProfile; label: string; description: string }> = [
  {
    id: 'jwt',
    label: 'JWT Session',
    description: 'Interactive browser login using JWT access and refresh tokens.',
  },
  {
    id: 'api_key',
    label: 'API Key',
    description: 'Service-to-service automation using generated API keys.',
  },
  {
    id: 'azure_confidential',
    label: 'Azure Confidential',
    description: 'Use Azure Key Vault and managed identity for confidential credential handling.',
  },
];

export default function SetupPage() {
  const router = useRouter();
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('Admin');
  const [password, setPassword] = useState('');
  const [generateApiKey, setGenerateApiKey] = useState(true);
  const [apiKeyName, setApiKeyName] = useState('mcp-default');
  const [authProfile, setAuthProfile] = useState<AuthProfile>('jwt');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SetupResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    const loadStatus = async () => {
      try {
        const res = await fetch('/api/setup/status', { cache: 'no-store' });
        const data = await res.json();
        if (!mounted) {
          return;
        }
        if (!res.ok) {
          setError(data.error || 'Failed to check setup status');
          return;
        }
        setSetupStatus(data);
        if (!data.setup_required) {
          router.replace('/login');
        }
      } catch {
        if (mounted) {
          setError('Unable to reach setup endpoint');
        }
      } finally {
        if (mounted) {
          setLoadingStatus(false);
        }
      }
    };

    void loadStatus();
    return () => {
      mounted = false;
    };
  }, [router]);

  const canSubmit = useMemo(() => {
    return email.trim().length > 0 && password.length >= 12 && !submitting;
  }, [email, password, submitting]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      const res = await fetch('/api/setup/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          name: name.trim() || 'Admin',
          password,
          generate_api_key: generateApiKey,
          api_key_name: apiKeyName.trim() || 'mcp-default',
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail || 'Setup failed');
      }

      setResult(data);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Setup failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (loadingStatus) {
    return <div className="flex min-h-screen items-center justify-center">Loading setup status...</div>;
  }

  if (result?.success) {
    return (
      <main className="mx-auto min-h-screen w-full max-w-2xl p-8">
        <h1 className="text-2xl font-semibold">Initial setup completed</h1>
        <p className="mt-2 text-sm text-muted-foreground">Admin account {result.email} was created.</p>

        {result.api_key ? (
          <section className="mt-6 rounded-md border border-amber-300 bg-amber-50 p-4 text-sm">
            <h2 className="font-semibold">Store this API key now</h2>
            <p className="mt-1 break-all font-mono">{result.api_key}</p>
            <p className="mt-2 text-xs text-muted-foreground">
              This value is shown once. Store it in a secure vault.
            </p>
          </section>
        ) : null}

        <section className="mt-6 rounded-md border p-4 text-sm">
          <h2 className="font-semibold">Selected access profile</h2>
          <p className="mt-1">{AUTH_PROFILE_OPTIONS.find((item) => item.id === authProfile)?.label}</p>
          <p className="text-muted-foreground">
            {AUTH_PROFILE_OPTIONS.find((item) => item.id === authProfile)?.description}
          </p>
        </section>

        <div className="mt-6 flex gap-3">
          <button
            onClick={() => router.push('/login')}
            className="rounded-md bg-[#016339] px-4 py-2 text-sm font-medium text-white"
          >
            Continue to login
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="mx-auto min-h-screen w-full max-w-2xl p-8">
      <h1 className="text-2xl font-semibold">AgentGate first-time setup</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        Initial setup can only be completed from this browser page.
      </p>

      {setupStatus ? (
        <p className="mt-2 text-xs text-muted-foreground">{setupStatus.message}</p>
      ) : null}

      {error ? (
        <div className="mt-4 rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-700">{error}</div>
      ) : null}

      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        <div>
          <label className="mb-1 block text-sm font-medium">Admin email</label>
          <input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            type="email"
            required
            className="w-full rounded-md border px-3 py-2 text-sm"
          />
        </div>

        <div>
          <label className="mb-1 block text-sm font-medium">Display name</label>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            type="text"
            required
            className="w-full rounded-md border px-3 py-2 text-sm"
          />
        </div>

        <div>
          <label className="mb-1 block text-sm font-medium">Password</label>
          <input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            type="password"
            required
            minLength={12}
            className="w-full rounded-md border px-3 py-2 text-sm"
          />
          <p className="mt-1 text-xs text-muted-foreground">
            Minimum 12 characters with uppercase, lowercase, number, and special character.
          </p>
        </div>

        <fieldset>
          <legend className="mb-1 block text-sm font-medium">Authentication profile</legend>
          <div className="space-y-2">
            {AUTH_PROFILE_OPTIONS.map((option) => (
              <label key={option.id} className="flex cursor-pointer items-start gap-2 rounded-md border p-3">
                <input
                  type="radio"
                  name="authProfile"
                  value={option.id}
                  checked={authProfile === option.id}
                  onChange={() => setAuthProfile(option.id)}
                  className="mt-1"
                />
                <div>
                  <div className="text-sm font-medium">{option.label}</div>
                  <div className="text-xs text-muted-foreground">{option.description}</div>
                </div>
              </label>
            ))}
          </div>
        </fieldset>

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={generateApiKey}
            onChange={(event) => setGenerateApiKey(event.target.checked)}
          />
          Generate API key during setup
        </label>

        {generateApiKey ? (
          <div>
            <label className="mb-1 block text-sm font-medium">API key name</label>
            <input
              value={apiKeyName}
              onChange={(event) => setApiKeyName(event.target.value)}
              type="text"
              className="w-full rounded-md border px-3 py-2 text-sm"
            />
          </div>
        ) : null}

        <button
          type="submit"
          disabled={!canSubmit}
          className="rounded-md bg-[#016339] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {submitting ? 'Completing setup...' : 'Complete setup'}
        </button>
      </form>
    </main>
  );
}
