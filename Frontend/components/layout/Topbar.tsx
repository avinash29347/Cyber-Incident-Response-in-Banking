"use client";

import { useEffect, useMemo, useState } from "react";
import { usePathname, useParams } from "next/navigation";
import { ShieldCheck, TimerReset, UserCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { getPipelineById } from "@/lib/mockData";
import { usePipeline } from "@/hooks/usePipeline";
import { severityTone } from "@/lib/utils";

export default function Topbar() {
  const pathname = usePathname();
  const params = useParams();
  const uploadedPipeline = usePipeline();
  const [timeLabel, setTimeLabel] = useState("--:--:--");

  useEffect(() => {
    const timer = window.setInterval(() => setTimeLabel(new Date().toLocaleTimeString()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  // Get incident data if on incident page
  const incidentId = Array.isArray(params?.id) ? params.id[0] : (params?.id as string | undefined);
  const pipeline = useMemo(() => {
    if (incidentId) return getPipelineById(incidentId, uploadedPipeline);
    return null;
  }, [incidentId, uploadedPipeline]);

  const isIncidentPage = pathname.startsWith("/incident");

  const title = useMemo(() => {
    if (isIncidentPage && pipeline) {
      return pipeline?.dashboard?.alert_title || "Incident Details";
    }
    if (pathname.startsWith("/upload")) return "Event Ingestion Pipeline";
    return "Security Operations Dashboard";
  }, [pathname, isIncidentPage, pipeline]);

  return (
    <header className="sticky top-0 z-20 border-b border-slate-700/70 bg-slate-900/80 px-4 py-3 backdrop-blur md:px-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Left: Title & Incident Info (HUD-style) */}
        <div className="flex-1">
          <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Cybersecurity</p>
          <div className="mt-1 flex items-center gap-3">
            <h2 className="text-sm font-semibold uppercase tracking-widest text-slate-400">{title}</h2>
            
            {/* Incident HUD Info */}
            {isIncidentPage && pipeline && (
              <div className="flex items-center gap-2 ml-2 pl-2 border-l border-slate-700/50">
                <div className="flex items-center gap-1">
                  <span className="text-xs text-slate-500">Severity:</span>
                  <Badge className={severityTone(pipeline?.dashboard?.severity)}>
                    {pipeline?.dashboard?.severity?.toUpperCase() || "LOW"}
                  </Badge>
                </div>
                <div className="hidden sm:flex items-center gap-1">
                  <span className="text-xs text-slate-500">Event:</span>
                  <span className="font-mono text-xs text-slate-400">{pipeline?.event_id}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Status Indicators */}
        <div className="flex flex-wrap items-center justify-end gap-3">
          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-xs text-slate-300">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-300" />
            Monitoring Active
          </span>
          <span className="inline-flex items-center gap-1 rounded-full border border-slate-600 bg-slate-800/80 px-2 py-1 text-xs text-slate-300">
            <TimerReset className="h-3.5 w-3.5" />
            Updated {timeLabel}
          </span>
          <button className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-950/80 px-3 py-1.5 text-xs text-slate-200 transition hover:border-sky-500/40 hover:shadow-[0_0_18px_rgba(56,189,248,0.18)]">
            <UserCircle2 className="h-4 w-4 text-sky-300" />
            Analyst
          </button>
        </div>
      </div>
    </header>
  );
}