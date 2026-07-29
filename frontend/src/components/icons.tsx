// Lightweight inline SVG icons (no dependency). Stroke uses currentColor.
type P = { className?: string };
const S = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor"
       strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}
       aria-hidden="true">{children}</svg>
);

export const Icon = {
  dashboard: (p: P) => <S {...p}><rect x="3" y="3" width="7" height="9" /><rect x="14" y="3" width="7" height="5" /><rect x="14" y="12" width="7" height="9" /><rect x="3" y="16" width="7" height="5" /></S>,
  devices: (p: P) => <S {...p}><rect x="2" y="4" width="20" height="13" rx="2" /><path d="M8 21h8M12 17v4" /></S>,
  customers: (p: P) => <S {...p}><circle cx="9" cy="8" r="3" /><path d="M3 20a6 6 0 0 1 12 0" /><path d="M16 5a3 3 0 0 1 0 6M21 20a6 6 0 0 0-4-5.6" /></S>,
  findings: (p: P) => <S {...p}><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" /><path d="M12 8v4M12 16h.01" /></S>,
  rules: (p: P) => <S {...p}><path d="M9 3h6l1 4H8zM6 7h12l-1 14H7z" /><path d="M10 12h4" /></S>,
  compliance: (p: P) => <S {...p}><path d="M9 11l2 2 4-4" /><rect x="4" y="4" width="16" height="16" rx="2" /></S>,
  trends: (p: P) => <S {...p}><path d="M3 17l5-5 4 4 8-8" /><path d="M16 8h5v5" /></S>,
  integrations: (p: P) => <S {...p}><path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" /><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" /></S>,
  platform: (p: P) => <S {...p}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18" /></S>,
  settings: (p: P) => <S {...p}><circle cx="12" cy="12" r="3" /><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.5-2.3 1a7 7 0 0 0-1.7-1l-.4-2.5h-4l-.4 2.5a7 7 0 0 0-1.7 1l-2.3-1-2 3.5 2 1.5a7 7 0 0 0 0 2l-2 1.5 2 3.5 2.3-1a7 7 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7 7 0 0 0 1.7-1l2.3 1 2-3.5-2-1.5a7 7 0 0 0 .1-1z" /></S>,
  logout: (p: P) => <S {...p}><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5M21 12H9" /></S>,
  sun: (p: P) => <S {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19" /></S>,
  moon: (p: P) => <S {...p}><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></S>,
  menu: (p: P) => <S {...p}><path d="M3 6h18M3 12h18M3 18h18" /></S>,
  close: (p: P) => <S {...p}><path d="M6 6l12 12M18 6L6 18" /></S>,
};

export type IconName = keyof typeof Icon;
