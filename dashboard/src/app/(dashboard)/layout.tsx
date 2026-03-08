"use client";

import React, { useState, useMemo, useRef, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession, signOut } from "next-auth/react";
import {
  LayoutDashboard,
  Menu,
  X,
  LogOut,
  ChevronDown,
  Sun,
  Moon,
  FlaskConical,
  Loader2,
  ShieldCheck,
  Settings,
  Scale,
  ClipboardCheck,
  BadgeCheck,
  Workflow,
  Microscope,
  TrendingUp,
} from "lucide-react";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DotPattern } from "@/components/ui/dot-pattern";
import { useRBAC } from "@/hooks/useRBAC";
import { canAccessPath } from "@/lib/rbac";

interface NavItem {
  href: string;
  label: string;
  icon: React.ReactNode;
}

interface NavGroup {
  label?: string;
  items: NavItem[];
}

const ALL_NAV_GROUPS: NavGroup[] = [
  {
    items: [
      {
        href: "/",
        label: "Overview",
        icon: <LayoutDashboard className="h-5 w-5" />,
      },
    ],
  },
  {
    label: "Showcase",
    items: [
      {
        href: "/architecture",
        label: "Architecture",
        icon: <Workflow className="h-5 w-5" />,
      },
      {
        href: "/technical",
        label: "Technical",
        icon: <Microscope className="h-5 w-5" />,
      },
      {
        href: "/market",
        label: "Market",
        icon: <TrendingUp className="h-5 w-5" />,
      },
      {
        href: "/verification",
        label: "Verification",
        icon: <BadgeCheck className="h-5 w-5" />,
      },
    ],
  },
  {
    label: "Operations",
    items: [
      {
        href: "/playground",
        label: "Playground",
        icon: <FlaskConical className="h-5 w-5" />,
      },
      {
        href: "/policies",
        label: "Policies",
        icon: <Scale className="h-5 w-5" />,
      },
      {
        href: "/pii",
        label: "Data Protection",
        icon: <ShieldCheck className="h-5 w-5" />,
      },
      {
        href: "/approvals",
        label: "Approvals",
        icon: <ClipboardCheck className="h-5 w-5" />,
      },
      {
        href: "/settings",
        label: "Settings",
        icon: <Settings className="h-5 w-5" />,
      },
    ],
  },
];

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const { data: session } = useSession();
  const { theme, toggleTheme } = useTheme();
  const { role, roleName, roleBadgeColor } = useRBAC();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const testModeEnabled = process.env.NEXT_PUBLIC_ENABLE_TEST_MODE === 'true';
  const [testMode, setTestMode] = useState(false);
  const [testLoading, setTestLoading] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setUserMenuOpen(false);
      }
    }
    if (userMenuOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [userMenuOpen]);

  // Filter nav groups based on user role
  const navGroups = useMemo(() => {
    return ALL_NAV_GROUPS
      .map((group) => ({
        ...group,
        items: group.items.filter(
          (item) => canAccessPath(role, item.href)
        ),
      }))
      .filter((group) => group.items.length > 0);
  }, [role]);

  // Load test mode from localStorage on mount and clear test data on initial login
  React.useEffect(() => {
    if (!testModeEnabled) return;
    const stored = localStorage.getItem('agentgate-test-mode');
    if (stored === 'true') {
      setTestMode(true);
    } else if (stored === null) {
      fetch('/api/test/clear', { method: 'DELETE' }).catch(() => {
        // Silently ignore errors on initial cleanup
      });
    }
  }, [testModeEnabled]);

  const handleTestMode = async () => {
    setTestLoading(true);
    setTestError(null);
    try {
      if (testMode) {
        // Clear test data when exiting
        const res = await fetch('/api/test/clear', { method: 'DELETE' });
        const data = await res.json();
        if (res.ok && data.success) {
          setTestMode(false);
          localStorage.removeItem('agentgate-test-mode');
          // Small delay to ensure DB transaction commits
          await new Promise(resolve => setTimeout(resolve, 500));
          // Force hard reload to clear all caches
          window.location.href = window.location.pathname;
        } else {
          setTestError(data.error || 'Failed to clear test data');
        }
      } else {
        // Seed test data when entering
        const res = await fetch('/api/test/seed', { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
          setTestMode(true);
          localStorage.setItem('agentgate-test-mode', 'true');
          // Small delay to ensure DB transaction commits
          await new Promise(resolve => setTimeout(resolve, 500));
          window.location.href = window.location.pathname;
        } else {
          setTestError(data.error || 'Failed to seed test data');
        }
      }
    } catch {
      setTestError('Failed to toggle test mode');
    } finally {
      setTestLoading(false);
    }
  };

  const handleSignOut = async () => {
    localStorage.removeItem('agentgate-test-mode');
    await signOut({ redirect: true, callbackUrl: "/login" });
  };

  return (
    <div className="relative flex h-screen overflow-hidden bg-background">
      {/* Background Pattern - subtle decorative dots with pointer-events disabled */}
      <DotPattern
        id="dashboard-dot-bg"
        className={cn(
          "absolute inset-0 z-0 fill-neutral-500/10 pointer-events-none",
          "[mask-image:radial-gradient(ellipse_at_center,transparent_40%,black_90%)]"
        )}
      />

      {/* Mobile backdrop */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-border bg-card/70 backdrop-blur-xl transition-transform duration-300 ease-out",
          "shadow-sm lg:relative lg:z-10 lg:translate-x-0 lg:transition-all lg:duration-300",
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full",
          !mobileMenuOpen && (sidebarOpen ? "lg:w-64" : "lg:w-20"),
        )}
      >
        {/* Logo */}
        <div className="flex items-center border-b border-border px-3 py-6">
          <Link href="/" className="flex items-center px-3">
            {sidebarOpen ? (
              <>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src="/logos/logo_dark_background.svg"
                  alt="AgentGate"
                  className="logo-dark h-8 w-auto"
                />
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src="/logos/logo_white_background.svg"
                  alt="AgentGate"
                  className="logo-light h-8 w-auto"
                />
              </>
            ) : (
              <>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src="/logos/Square_icon_black_background.svg"
                  alt="AG"
                  className="logo-dark h-8 w-8"
                />
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src="/logos/Square_icon_white_background.svg"
                  alt="AG"
                  className="logo-light h-8 w-8"
                />
              </>
            )}
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto px-3 py-6">
          <div className="space-y-4">
            {navGroups.map((group, groupIdx) => (
              <div key={group.label || groupIdx}>
                {group.label ? (
                  sidebarOpen ? (
                    <p className={cn(
                      "mb-2 px-3 text-xs font-semibold",
                      "uppercase tracking-wider",
                      "text-muted-foreground"
                    )}>
                      {group.label}
                    </p>
                  ) : (
                    <div className="mx-3 border-t border-border" />
                  )
                ) : null}
                <div className="space-y-1">
                  {group.items.map((item) => {
                    const isActive =
                      item.href === "/"
                        ? pathname === "/"
                        : pathname.startsWith(item.href);
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        onClick={() => setMobileMenuOpen(false)}
                        className={cn(
                          "flex items-center gap-3",
                          "rounded-lg px-3 py-2",
                          "text-sm transition-smooth",
                          isActive
                            ? "bg-primary/[0.07]"
                              + " font-semibold"
                              + " text-primary"
                            : "font-medium"
                              + " text-muted-foreground"
                              + " hover:bg-muted"
                              + " hover:text-foreground",
                        )}
                        title={
                          !sidebarOpen
                            ? item.label
                            : undefined
                        }
                      >
                        <div className="flex h-5 w-5 items-center justify-center">
                          {item.icon}
                        </div>
                        {sidebarOpen && (
                          <span>{item.label}</span>
                        )}
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </nav>

        {/* Sidebar Footer */}
        <div className="hidden border-t border-border px-3 py-4 lg:block">
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-center"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label="Toggle sidebar"
          >
            {sidebarOpen ? (
              <X className="h-4 w-4" />
            ) : (
              <Menu className="h-4 w-4" />
            )}
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="relative z-10 flex flex-1 flex-col overflow-visible">
        {/* Header */}
        <header className={cn(
          "relative z-40 overflow-visible border-b px-4 py-3 transition-colors backdrop-blur-xl lg:px-6",
          testMode
            ? "border-amber-500/50 bg-amber-500/10"
            : "border-border bg-card/70"
        )}>
          <div className="flex items-center justify-between gap-4">
            {/* Hamburger (mobile only) */}
            <Button
              variant="ghost"
              size="sm"
              className="h-10 w-10 p-0 lg:hidden"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open menu"
            >
              <Menu className="h-5 w-5" />
            </Button>

            {/* Page Title */}
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-semibold text-foreground">
                {navGroups
                  .flatMap((g) => g.items)
                  .find((item) =>
                    item.href === "/"
                      ? pathname === "/"
                      : pathname.startsWith(item.href)
                  )?.label || "Dashboard"}
              </h1>
              {testMode && (
                <span className="rounded-full bg-amber-500 px-2.5 py-0.5 text-xs font-semibold text-black">
                  TEST MODE
                </span>
              )}
            </div>

            {/* Header Actions */}
            <div className="flex items-center gap-2">
              {/* Test Mode Toggle - only shown when NEXT_PUBLIC_ENABLE_TEST_MODE=true */}
              {testModeEnabled && (
                <>
                  <Button
                    variant={testMode ? "primary" : "ghost"}
                    size="sm"
                    onClick={handleTestMode}
                    disabled={testLoading}
                    className={cn(
                      "h-10 gap-2 rounded-lg px-3",
                      testMode && "bg-amber-500 text-black hover:bg-amber-600"
                    )}
                  >
                    {testLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <FlaskConical className="h-4 w-4" />
                    )}
                    <span className="hidden sm:inline">
                      {testMode ? "Exit Test" : "Test Mode"}
                    </span>
                  </Button>
                  {testError && (
                    <span className="text-xs text-destructive">{testError}</span>
                  )}
                </>
              )}

              {/* Theme Toggle */}
              <Button
                variant="ghost"
                size="sm"
                onClick={toggleTheme}
                className="h-10 w-10 rounded-lg p-0"
                aria-label="Toggle theme"
              >
                {theme === "dark" ? (
                  <Sun className="h-5 w-5 text-muted-foreground" />
                ) : (
                  <Moon className="h-5 w-5 text-muted-foreground" />
                )}
              </Button>

              {/* Divider */}
              <div className="mx-2 h-6 w-px bg-border" />

              {/* User Menu */}
              <div className="relative z-50" ref={userMenuRef}>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                  className="flex h-10 items-center gap-3 rounded-lg px-2"
                >
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
                    {session?.user?.name?.charAt(0).toUpperCase() || session?.user?.email?.charAt(0).toUpperCase() || "U"}
                  </div>
                  <div className="hidden text-left md:block">
                    <p className="text-sm font-medium text-foreground">
                      {session?.user?.name || "User"}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {session?.user?.email}
                    </p>
                  </div>
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                </Button>

                {userMenuOpen && (
                  <div
                    className="absolute right-0 top-full z-[70] mt-2 w-56 rounded-lg border border-border bg-card p-2 shadow-2xl pointer-events-auto"
                  >
                    <div className="border-b border-border px-3 py-3">
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-medium text-foreground">
                          {session?.user?.name || "User"}
                        </p>
                        {role && (
                          <Badge className={cn("text-xs", roleBadgeColor)}>
                            {roleName}
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {session?.user?.email}
                      </p>
                    </div>
                    <div className="py-1">
                      <Link
                        href="/settings"
                        onClick={() => setUserMenuOpen(false)}
                        className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-foreground hover:bg-muted"
                      >
                        <Settings className="h-4 w-4" />
                        Settings
                      </Link>
                      <button
                        onClick={() => {
                          setUserMenuOpen(false);
                          handleSignOut();
                        }}
                        className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-destructive hover:bg-destructive/10"
                      >
                        <LogOut className="h-4 w-4" />
                        Sign out
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto bg-background/95">
          <div className="p-4 sm:p-6 lg:p-8">{children}</div>
        </main>
      </div>
    </div>
  );
}
