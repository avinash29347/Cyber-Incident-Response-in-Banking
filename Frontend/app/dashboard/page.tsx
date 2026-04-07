"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EventPipeline, getAllMockPipelines, readSimulatedEvents } from "@/lib/mockData";
import { severityTone } from "@/lib/utils";
import { usePipeline } from "@/hooks/usePipeline";

type JsonEvent = Record<string, any>;

function normalizeSeverity(value: string | undefined | null): string {
	const normalized = String(value ?? "low").toLowerCase();
	if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
		return normalized;
	}
	return "low";
}

function normalizeEventToPipeline(event: JsonEvent, index: number): EventPipeline {
	const severity = normalizeSeverity(event?.detection?.severity || event?.dashboard?.severity);
	const eventId = event?.event_id || event?.incident_id || `evt-json-${index + 1}`;

	const alertTitle =
		event?.dashboard?.alert_title ||
		event?.summary ||
		event?.ai_analysis?.intent ||
		event?.detection?.threat_type?.replaceAll("_", " ") ||
		"Unknown Alert";

	const affectedUser =
		event?.dashboard?.affected_user ||
		event?.raw_event?.affected_user ||
		event?.raw_event?.user ||
		"anonymous";

	const sourceIp =
		event?.dashboard?.source_ip ||
		event?.raw_event?.source_ip ||
		event?.raw_event?.src_ip ||
		"N/A";

	const aiSummary =
		event?.ai_analysis?.one_liner ||
		event?.ai_analysis?.summary ||
		event?.ai_analysis?.narrative ||
		event?.detection?.reasoning?.[0] ||
		event?.summary ||
		"Investigation context available in incident workspace.";

	const status = String(event?.final_report?.status ?? event?.status ?? "open").toLowerCase();

	return {
		...(event as EventPipeline),
		event_id: eventId,
		dashboard: {
			...(event?.dashboard ?? {}),
			alert_title: alertTitle,
			severity,
			affected_user: affectedUser,
			source_ip: sourceIp,
		},
		ai_analysis: {
			...(event?.ai_analysis ?? {}),
			one_liner: event?.ai_analysis?.one_liner ?? aiSummary,
			summary: event?.ai_analysis?.summary ?? aiSummary,
		},
		final_report: {
			...(event?.final_report ?? {}),
			status,
		},
	};
}

export default function DashboardPage() {
	const uploadedPipeline = usePipeline();
	const [jsonPipelines, setJsonPipelines] = useState<EventPipeline[]>([]);
	const [simPipelines, setSimPipelines] = useState<EventPipeline[]>([]);
	const [jsonLoaded, setJsonLoaded] = useState(false);

	// Load simulated events from localStorage on mount — newest first
	useEffect(() => {
		const sims = readSimulatedEvents();
		// Sort by timestamp in raw_event descending (newest run first)
		sims.sort((a, b) => {
			const ta = (a as any)?.raw_event?.timestamp ?? "";
			const tb = (b as any)?.raw_event?.timestamp ?? "";
			return tb.localeCompare(ta);
		});
		setSimPipelines(sims);
	}, []);

	useEffect(() => {
		let isMounted = true;

		async function loadFrontendOutput() {
			try {
				const res = await fetch("/frontend_output.json", { cache: "no-store" });

				if (!res.ok) {
					throw new Error(`Failed to fetch frontend_output.json: ${res.status}`);
				}

				const data = await res.json();

				if (!isMounted) return;

				const rawEvents = Array.isArray(data) ? data : Array.isArray(data?.events) ? data.events : [];

				const normalized = rawEvents.map((event: JsonEvent, index: number) =>
					normalizeEventToPipeline(event, index)
				);

				setJsonPipelines(normalized);
			} catch (error) {
				console.error("Error loading frontend_output.json:", error);
				if (isMounted) {
					setJsonPipelines([]);
				}
			} finally {
				if (isMounted) {
					setJsonLoaded(true);
				}
			}
		}

		loadFrontendOutput();

		return () => {
			isMounted = false;
		};
	}, []);

	const incidents = useMemo(() => {
		const mock = getAllMockPipelines();
		// Priority: simulated events > JSON file events > mock data
		const base = simPipelines.length > 0
			? simPipelines
			: jsonPipelines.length > 0
				? jsonPipelines
				: mock;

		if (uploadedPipeline) {
			return [uploadedPipeline, ...base.filter((item) => item.event_id !== uploadedPipeline.event_id)];
		}

		return base;
	}, [uploadedPipeline, jsonPipelines, simPipelines]);

	const summary = useMemo(() => {
		const totalIncidents = incidents.length;
		const criticalAlerts = incidents.filter(
			(item) => String(item.dashboard?.severity ?? "low").toLowerCase() === "critical"
		).length;
		const activeInvestigations = incidents.filter((item) => {
			const status = String(item.final_report?.status ?? "open").toLowerCase();
			return status !== "closed";
		}).length;

		return { totalIncidents, criticalAlerts, activeInvestigations };
	}, [incidents]);

	const getDescription = (pipeline: EventPipeline) => {
		return (
			pipeline.ai_analysis?.one_liner ||
			pipeline.ai_analysis?.summary ||
			(pipeline as any)?.detection?.reasoning?.[0] ||
			(pipeline as any)?.ai_analysis?.narrative ||
			"Investigation context available in incident workspace."
		);
	};

	return (
		<motion.div
			className="space-y-6"
			initial={{ opacity: 0 }}
			animate={{ opacity: 1 }}
			transition={{ duration: 0.3 }}
		>
			<section className="rounded-xl border border-slate-700/80 bg-slate-900/60 p-5 shadow-lg">
				<h1 className="text-sm font-semibold uppercase tracking-widest text-slate-400">SENTRA Mission Board</h1>
				<p className="mt-1 text-sm text-slate-300">
					Critical incidents, analyst workload, and active investigations.
				</p>

				<div className="mt-2 text-xs text-slate-500">
					{jsonLoaded
						? jsonPipelines.length > 0
							? "Live dashboard data loaded from frontend_output.json"
							: "frontend_output.json not found or empty — showing fallback mock incidents"
						: "Loading incident feed..."}
				</div>

				<div className="mt-4 flex flex-wrap gap-2">
					<Link href="/upload">
						<Button>Upload Event JSON</Button>
					</Link>
					<Link href={`/incident/${incidents[0]?.event_id ?? "evt-2026-04-001"}`}>
						<Button variant="outline">Open Latest Incident</Button>
					</Link>
				</div>
			</section>

			<section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
				<SummaryMetric label="Total Incidents" value={summary.totalIncidents} tone="slate" />
				<SummaryMetric label="Critical Alerts" value={summary.criticalAlerts} tone="critical" />
				<SummaryMetric label="Active Investigations" value={summary.activeInvestigations} tone="active" />
			</section>

			<section className="space-y-4">
				<h2 className="text-sm font-semibold uppercase tracking-widest text-slate-400">Incident Queue</h2>

				<div className="grid gap-4 md:grid-cols-2">
					{incidents.map((pipeline: EventPipeline, index) => {
						const severity = String(pipeline.dashboard?.severity ?? "low").toLowerCase();
						const isCritical = severity === "critical";
						const description = getDescription(pipeline);

						return (
							<motion.div
								key={pipeline.event_id}
								initial={{ opacity: 0, y: 10 }}
								animate={
									isCritical
										? {
												opacity: 1,
												y: 0,
												boxShadow: [
													"0 0 0 rgba(239,68,68,0.0)",
													"0 0 20px rgba(239,68,68,0.22)",
													"0 0 0 rgba(239,68,68,0.0)",
												],
										  }
										: { opacity: 1, y: 0 }
								}
								transition={
									isCritical
										? {
												opacity: { duration: 0.25, delay: index * 0.05 },
												y: { duration: 0.25, delay: index * 0.05 },
												boxShadow: { duration: 2.2, repeat: Infinity, ease: "easeInOut", delay: 0.5 },
										  }
										: { duration: 0.25, delay: index * 0.05 }
								}
								className={`rounded-xl border p-4 shadow-lg transition ${
									isCritical
										? "border-red-500/60 bg-red-950/20 shadow-[0_0_20px_rgba(239,68,68,0.18)]"
										: "border-slate-700 bg-slate-900/65"
								}`}
							>
								<div className="mb-3 flex items-start justify-between gap-3">
									<div>
										<p className="text-sm font-semibold text-slate-100">
											{pipeline.dashboard?.alert_title ?? "Unknown Alert"}
										</p>
										<p className="mt-1 font-mono text-xs text-slate-500">
											Event ID: {pipeline.event_id}
										</p>
									</div>
									<Badge className={severityTone(pipeline.dashboard?.severity)}>
										{pipeline.dashboard?.severity ?? "low"}
									</Badge>
								</div>

								<div className="space-y-1 text-xs text-slate-300">
									<p>User: {pipeline.dashboard?.affected_user ?? "N/A"}</p>
									<p>Source IP: {pipeline.dashboard?.source_ip ?? "N/A"}</p>
									<p className="line-clamp-2 text-slate-400">{description}</p>
								</div>

								<Link href={`/incident/${pipeline.event_id}`} className="mt-4 inline-block">
									<Button size="sm" variant={isCritical ? "destructive" : "secondary"}>
										Open Incident
									</Button>
								</Link>
							</motion.div>
						);
					})}
				</div>
			</section>
		</motion.div>
	);
}

function SummaryMetric({
	label,
	value,
	tone,
}: {
	label: string;
	value: number;
	tone: "slate" | "critical" | "active";
}) {
	const toneClass =
		tone === "critical"
			? "border-red-500/50 bg-red-950/30 text-red-200"
			: tone === "active"
				? "border-amber-500/40 bg-amber-950/20 text-amber-200"
				: "border-slate-700 bg-slate-900/60 text-slate-200";

	return (
		<motion.div
			className={`rounded-xl border p-4 ${toneClass}`}
			initial={{ opacity: 0, y: 8 }}
			animate={{ opacity: 1, y: 0 }}
			transition={{ duration: 0.25 }}
		>
			<p className="text-xs uppercase tracking-widest text-slate-400">{label}</p>
			<p className="mt-2 text-2xl font-bold leading-none">{value}</p>
		</motion.div>
	);
}