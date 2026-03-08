"use client";

import React, { createContext, useContext, useEffect, useState } from "react";

type Theme = "dark" | "light";

interface ThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("theme") as Theme | null;
    let themeToUse: Theme = "dark";
    if (stored) {
      themeToUse = stored;
    } else if (window.matchMedia("(prefers-color-scheme: light)").matches) {
      themeToUse = "light";
    }

    requestAnimationFrame(() => {
      setMounted(true);
      setTheme(themeToUse);
      document.documentElement.setAttribute("data-theme", themeToUse);
    });
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === "dark" ? "light" : "dark";
    setTheme(newTheme);
    localStorage.setItem("theme", newTheme);
    document.documentElement.setAttribute("data-theme", newTheme);
  };

  if (!mounted) {
    return <>{children}</>;
  }

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  // Return defaults during SSR/static generation
  if (context === undefined) {
    return {
      theme: "dark" as Theme,
      toggleTheme: () => {},
    };
  }
  return context;
}
