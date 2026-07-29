// Shared presentation helpers.

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const sevColor: Record<string, string> = {
  Critical: "#ff4d4d",
  High: "#ff8a3d",
  Medium: "#f5c451",
  Low: "#4a9eff",
  Info: "#7a879b",
};

export const sevTextClass: Record<string, string> = {
  Critical: "text-sev-critical",
  High: "text-sev-high",
  Medium: "text-sev-medium",
  Low: "text-sev-low",
  Info: "text-sev-info",
};

// Grade -> color for the gauge and grade letterform.
export function gradeColor(grade: string): string {
  switch (grade) {
    case "Secure":
    case "A":
      return "#39d98a";
    case "B":
      return "#9ad94a";
    case "C":
      return "#f5c451";
    case "D":
      return "#ff8a3d";
    default:
      return "#ff4d4d";
  }
}

// Finding workflow status -> human label and color.
export const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  in_progress: "In Progress",
  fixed: "Fixed",
  false_positive: "False Positive",
  accepted_risk: "Accepted Risk",
  suppressed: "Suppressed",
};

export const statusColor: Record<string, string> = {
  open: "#ff8a3d",
  acknowledged: "#f5c451",
  in_progress: "#4a9eff",
  fixed: "#39d98a",
  false_positive: "#7a879b",
  accepted_risk: "#9ad94a",
  suppressed: "#6b7689",
};

export const ACTIVE_STATUSES = ["open", "acknowledged", "in_progress"];

export function fmtDate(iso: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
