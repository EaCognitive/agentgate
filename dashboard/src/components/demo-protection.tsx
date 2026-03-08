"use client";

import { useEffect } from "react";

/**
 * Blocks common content-capture shortcuts (print, save, dev tools)
 * in demo/investor environments. Activated by NEXT_PUBLIC_DEMO_MODE=true.
 */
export function DemoProtection() {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const ctrl = e.ctrlKey || e.metaKey;

      // Block: Ctrl+S (save), Ctrl+P (print), Ctrl+Shift+I (devtools)
      if (ctrl && (e.key === "s" || e.key === "p")) {
        e.preventDefault();
        return;
      }
      if (ctrl && e.shiftKey && e.key === "I") {
        e.preventDefault();
        return;
      }
      // Block F12 (devtools)
      if (e.key === "F12") {
        e.preventDefault();
      }
    };

    const contextHandler = (e: MouseEvent) => {
      e.preventDefault();
    };

    document.addEventListener("keydown", handler);
    document.addEventListener("contextmenu", contextHandler);

    return () => {
      document.removeEventListener("keydown", handler);
      document.removeEventListener("contextmenu", contextHandler);
    };
  }, []);

  return null;
}
