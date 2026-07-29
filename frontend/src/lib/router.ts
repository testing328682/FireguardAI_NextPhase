// Minimal hash-based router — keeps the SPA dependency-free.
//
// Routes are stored in `location.hash` as `#/path`. `useHashRoute` returns the
// current path and re-renders on change; `navigate` updates the hash. Matching
// is done by the caller with `matchRoute`.

import { useEffect, useState } from "react";

export function currentPath(): string {
  const h = window.location.hash.replace(/^#/, "");
  return h || "/dashboard";
}

export function navigate(path: string) {
  window.location.hash = path;
}

export function useHashRoute(): string {
  const [path, setPath] = useState<string>(currentPath());
  useEffect(() => {
    const onChange = () => setPath(currentPath());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return path;
}

// Match `/findings/:id` style patterns. Returns the captured params or null.
export function matchRoute(pattern: string, path: string): Record<string, string> | null {
  const pp = pattern.split("/").filter(Boolean);
  const ap = path.split("/").filter(Boolean);
  if (pp.length !== ap.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < pp.length; i++) {
    if (pp[i].startsWith(":")) params[pp[i].slice(1)] = decodeURIComponent(ap[i]);
    else if (pp[i] !== ap[i]) return null;
  }
  return params;
}
