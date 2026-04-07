"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { AnimatePresence } from "framer-motion";
import Sidebar from "@/components/layout/Sidebar";
import Topbar from "@/components/layout/Topbar";
import EntryScreen from "@/components/layout/EntryScreen";

type Props = {
  children: React.ReactNode;
};

export default function AppShell({ children }: Props) {
  const pathname = usePathname();
  const [showEntry, setShowEntry] = useState(pathname === "/dashboard");

  useEffect(() => {
    let syncTimer: number | undefined;

    if (pathname !== "/dashboard") {
      syncTimer = window.setTimeout(() => {
        setShowEntry(false);
      }, 0);

      return () => {
        if (syncTimer) window.clearTimeout(syncTimer);
      };
    }

    syncTimer = window.setTimeout(() => {
      setShowEntry(true);
    }, 0);

    const hideTimer = window.setTimeout(() => {
      setShowEntry(false);
    }, 1200);

    return () => {
      if (syncTimer) window.clearTimeout(syncTimer);
      if (hideTimer) window.clearTimeout(hideTimer);
    };
  }, [pathname]);

  return (
    <>
      <AnimatePresence>{showEntry ? <EntryScreen /> : null}</AnimatePresence>
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <main className="flex-1 p-4 md:p-6">{children}</main>
        </div>
      </div>
    </>
  );
}
