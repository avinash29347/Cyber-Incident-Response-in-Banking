"use client";

import { EventPipeline } from "@/lib/mockData";
import { Badge } from "@/components/ui/badge";
import { severityTone } from "@/lib/utils";

type Props = {
  pipeline: EventPipeline;
  timestamp?: string;
  status: "Open" | "Investigating" | "Closed";
  onStatusChange?: (status: "Open" | "Investigating" | "Closed") => void;
  onAction?: (action: "Block IP" | "Reset Password" | "Investigate") => void;
};

export default function AlertSummaryPanel({ pipeline }: Props) {
  const eventId = pipeline?.event_id || "unknown";

  return (
    <section className="sticky top-0 z-50 border-b border-slate-700 bg-slate-900/95 p-3 backdrop-blur">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-base font-semibold leading-relaxed text-slate-100">{pipeline?.dashboard?.alert_title ?? "Unknown Alert"}</span>
        <Badge className={severityTone(pipeline?.dashboard?.severity)}>{pipeline?.dashboard?.severity?.toUpperCase() ?? "LOW"}</Badge>
        <span className="font-mono text-slate-400">Event ID: {eventId}</span>
      </div>
    </section>
  );
}
