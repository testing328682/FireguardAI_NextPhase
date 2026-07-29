// Light/dark theme stored on <html data-theme> and persisted to localStorage.
export type Theme = "dark" | "light";

const KEY = "fgai_theme";

export function getTheme(): Theme {
  const v = localStorage.getItem(KEY);
  return v === "light" ? "light" : "dark";
}

export function applyTheme(t: Theme): void {
  document.documentElement.dataset.theme = t;
  localStorage.setItem(KEY, t);
}

export function initTheme(): void {
  applyTheme(getTheme());
}

export function toggleTheme(): Theme {
  const next: Theme = getTheme() === "dark" ? "light" : "dark";
  applyTheme(next);
  return next;
}
