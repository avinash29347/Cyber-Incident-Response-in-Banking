"use client";

import { useState } from "react";
import { EventPipeline } from "@/lib/mockData";
import CardBlock from "@/components/cards/CardBlock";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, CircleDashed, Loader2 } from "lucide-react";
import EntityPivot from "@/components/shared/EntityPivot";
import { updateIncidentStatus, type IncidentAction } from "@/lib/api";

type Props = {
  pipeline: EventPipeline;
  onAction?: (action: "Block IP" | "Reset Password" | "Disable User") => void;
  onFalsePositive?: () => void;
};

export default function ResponseCard({ pipeline, onAction, onFalsePositive }: Props) {
  const actions = ["Block IP", "Reset Password", "Disable User"] as const;
  const recommendedActions = pipeline?.response?.recommended_actions?.length
    ? pipeline.response.recommended_actions
    : ["No recommended actions provided"];
  const [pendingAction, setPendingAction] = useState<IncidentAction | null>(null);
  const [feedback, setFeedback] = useState<{ tone: "success" | "error"; message: string } | null>(null);

  const runBackendAction = async (action: IncidentAction) => {
    if (!pipeline?.event_id || pendingAction) return;

    setPendingAction(action);
    setFeedback(null);

    try {
      const result = await updateIncidentStatus(pipeline.event_id, action);
      setFeedback({ tone: "success", message: result.message });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Action failed. Please retry.";
      setFeedback({ tone: "error", message });
    } finally {
      setPendingAction(null);
    }
  };

  return (
    <CardBlock title="Response Playbook" tag="Layer 11" severity={pipeline?.dashboard?.severity}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="border-sky-500/40 text-sky-200">
            Priority {pipeline?.response?.priority ?? "P4"}
          </Badge>
          <Badge variant="outline" className="border-emerald-500/40 text-emerald-200">
            Status ready for action
          </Badge>
          <EntityPivot type="ip" value={pipeline?.dashboard?.source_ip ?? "N/A"} />
          <EntityPivot type="user" value={pipeline?.dashboard?.affected_user ?? "N/A"} />
        </div>

        <div className="flex flex-col gap-3">
          <Checklist title="Recommended Actions" items={recommendedActions} />
          <Checklist
            title="Containment Steps"
            items={
              pipeline?.response?.containment_steps?.length
                ? pipeline?.response?.containment_steps
                : ["No containment steps provided"]
            }
          />
        </div>

        <div className="flex flex-col gap-2">
          {actions.map((action, index) => (
            <Button
              key={action}
              variant={index === 0 ? "default" : index === 1 ? "secondary" : "outline"}
              className="h-9 w-full"
              onClick={() => onAction?.(action)}
            >
              {action}
            </Button>
          ))}
        </div>

        <div className="grid gap-2 md:grid-cols-2">
          <Button
            variant="default"
            disabled={pendingAction !== null}
            onClick={() => runBackendAction("true_positive")}
            className="gap-2"
          >
            {pendingAction === "true_positive" ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
            Mark as True Positive
          </Button>
          <Button
            variant="outline"
            disabled={pendingAction !== null}
            onClick={async () => {
              await runBackendAction("false_positive");
              onFalsePositive?.();
            }}
            className="gap-2"
          >
            {pendingAction === "false_positive" ? <Loader2 className="h-4 w-4 animate-spin" /> : <CircleDashed className="h-4 w-4" />}
            Mark as False Positive
          </Button>
          <Button
            variant="secondary"
            disabled={pendingAction !== null}
            onClick={() => runBackendAction("escalate")}
            className="gap-2"
          >
            {pendingAction === "escalate" ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
            Escalate
          </Button>
          <Button
            variant="destructive"
            disabled={pendingAction !== null}
            onClick={() => runBackendAction("contain")}
            className="gap-2"
          >
            {pendingAction === "contain" ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
            Contain
          </Button>
        </div>

        {feedback ? (
          <div
            className={`rounded-sm border px-3 py-2 text-xs ${
              feedback.tone === "success"
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                : "border-red-500/40 bg-red-500/10 text-red-200"
            }`}
          >
            {feedback.message}
          </div>
        ) : null}
      </div>
    </CardBlock>
  );
}

function Checklist({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-sm border border-slate-700/60 bg-slate-950/60 p-3">
      <p className="mb-2 text-xs uppercase tracking-[0.14em] text-slate-400">{title}</p>
      <ul className="divide-y divide-slate-800 text-sm text-slate-200">
        {items.map((item, index) => (
          <li key={`${title}-${index}`} className="flex items-start gap-2 py-1.5">
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 text-emerald-300" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
