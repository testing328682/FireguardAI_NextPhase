import { gradeColor } from "../lib/ui";
import type { ScoreBlock } from "../lib/types";

// ── Animated security score gauge ─────────────────────────────────────
export function ScoreGauge({ score }: { score: ScoreBlock }) {
  const value = Math.max(0, Math.min(100, score.score));
  const color = gradeColor(score.grade);

  const size = 220;
  const stroke = 16;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const startAngle = 135;
  const sweep = 270;
  const circ = 2 * Math.PI * r;
  const arcLen = (sweep / 360) * circ;
  const filled = (value / 100) * arcLen;

  const polar = (angle: number) => {
    const a = ((angle - 90) * Math.PI) / 180;
    return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
  };
  const p0 = polar(startAngle);
  const p1 = polar(startAngle + sweep);
  const largeArc = sweep > 180 ? 1 : 0;
  const trackPath = `M ${p0.x} ${p0.y} A ${r} ${r} 0 ${largeArc} 1 ${p1.x} ${p1.y}`;

  return (
    <div className="relative inline-flex items-center justify-center">
      {/* Glow behind the gauge */}
      <svg width={size + 40} height={size + 40} viewBox={`-20 -20 ${size + 40} ${size + 40}`}
           className="absolute" aria-hidden="true">
        <defs>
          <filter id={`gaugeGlow-${score.grade}`}>
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>
        <path d={trackPath} fill="none" stroke={color} strokeWidth={stroke}
              strokeLinecap="round" opacity={0.12}
              filter={`url(#gaugeGlow-${score.grade})`}
              strokeDasharray={`${filled} ${circ}`} />
      </svg>

      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
           aria-label={`Security score ${value} of 100, grade ${score.grade}`}>
        {/* Track */}
        <path d={trackPath} fill="none" stroke="rgb(31,40,56)" strokeWidth={stroke}
              strokeLinecap="round" />
        {/* Filled arc */}
        <path
          d={trackPath}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circ}`}
          style={{
            transition: "stroke-dasharray 1.2s cubic-bezier(.2,.7,.2,1)",
            filter: `drop-shadow(0 0 8px ${color}44)`,
          }}
        />
        {/* Tick marks */}
        {[0, 25, 50, 75, 100].map((tick) => {
          const angle = startAngle + (sweep * tick) / 100;
          const a = ((angle - 90) * Math.PI) / 180;
          const inner = r - stroke / 2 - 2;
          const outer = r + stroke / 2 + 4;
          return (
            <line key={tick}
              x1={cx + inner * Math.cos(a)} y1={cy + inner * Math.sin(a)}
              x2={cx + outer * Math.cos(a)} y2={cy + outer * Math.sin(a)}
              stroke="rgb(var(--ink-500))" strokeWidth="1.5" opacity={0.4} />
          );
        })}
      </svg>

      {/* Center content */}
      <div className="absolute flex flex-col items-center">
        <span className="font-display font-bold leading-none"
              style={{
                fontSize: 58,
                color,
                textShadow: `0 0 20px ${color}44`,
              }}>
          {score.grade === "Secure" ? "A+" : score.grade}
        </span>
        <span className="font-mono text-ink-300 text-[13px] mt-1 tabular-nums font-medium">
          {value.toFixed(0)}
          <span className="text-ink-500">/100</span>
        </span>
        <span className="font-sans text-ink-500 text-[10px] uppercase tracking-[0.2em] mt-1.5">
          {score.grade_label}
        </span>
      </div>
    </div>
  );
}
