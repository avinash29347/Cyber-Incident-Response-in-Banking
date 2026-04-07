"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, FileWarning, UploadCloud } from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/dashboard", label: "SOC Dashboard", icon: Activity },
  { href: "/upload", label: "Ingest JSON", icon: UploadCloud },
  { href: "/incident/evt-2026-04-001", label: "Active Incident", icon: FileWarning },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden w-72 border-r border-slate-700/60 bg-slate-950/80 p-4 md:block">
      <div className="mb-8 rounded-xl border border-sky-500/30 bg-sky-950/30 p-4 shadow-lg shadow-sky-500/10">
        <p className="text-xs uppercase tracking-[0.18em] text-sky-300">Sentra</p>
        <h1 className="mt-1 text-sm font-semibold uppercase tracking-widest text-slate-400">SOC Console</h1>
        <p className="mt-2 text-xs text-slate-300">Threat Detection and Incident Response Platform</p>
      </div>

      <nav className="space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg border px-3 py-2 text-sm transition",
                isActive
                  ? "border-sky-500/40 bg-sky-900/30 text-sky-100"
                  : "border-transparent bg-slate-900/50 text-slate-300 hover:border-slate-700 hover:text-white",
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}