import { useMemo } from "react";
import { EventPipeline } from "@/lib/mockData";

type Props = {
  pipeline: EventPipeline;
};

export default function TemporalSparkline({ pipeline }: Props) {
  const bars = useMemo(() => {
    const confidence = Math.round((pipeline?.detection?.confidence ?? 0) * 100);
    const cvss = Math.round((pipeline?.cvss?.base_score ?? 0) * 10);
    const anomaly = Math.round((pipeline?.anomaly_detection?.anomaly_score ?? 0) * 100);
    const linked = Number(pipeline?.correlation_analysis?.linked_events ?? 1) * 6;

    const raw = [10, 16, 12, Math.max(12, anomaly), 22, Math.max(14, confidence), 18, Math.max(10, cvss), Math.max(12, linked), 20, 14, 12];
    return raw.map((height) => Math.max(8, Math.min(height, 96)));
  }, [pipeline]);

  return (
    <div className="rounded-sm border border-slate-700/50 bg-slate-950/60 p-3">
      <p className="text-sm font-semibold uppercase tracking-widest text-slate-400">Temporal Sparkline</p>
      <div className="mt-2 flex h-16 items-end gap-1">
        {bars.map((height, index) => (
          <div
            key={`spark-${index}`}
            className="w-2 rounded-sm bg-sky-500/70"
            style={{ height: `${height}%` }}
          />
        ))}
      </div>
    </div>
  );
}