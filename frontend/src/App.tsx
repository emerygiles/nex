import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNexRun } from "./hooks/useNexRun";
import { useCoverage, useHealth } from "./hooks/queries";
import type { View } from "./lib/types";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import StatBar from "./components/StatBar";
import GapAlert from "./components/GapAlert";
import CoverageGraph from "./components/CoverageGraph";
import ActivityStream from "./components/ActivityStream";
import DetectionPanel from "./components/DetectionPanel";
import EnvironmentPanel from "./components/EnvironmentPanel";
import TechniqueTable from "./components/TechniqueTable";
import DetectionsTable from "./components/DetectionsTable";

const META: Record<View, { title: string; subtitle: string }> = {
  coverage: { title: "Detection Coverage", subtitle: "Autonomous gap analysis across your Splunk telemetry" },
  surface: { title: "Surface Map", subtitle: "Every ATT&CK technique observed, mapped to current coverage" },
  detections: { title: "Detections", subtitle: "Deployed saved-search detections — baseline and NEX-authored" },
  activity: { title: "Activity", subtitle: "The agent's reasoning and tool calls, step by step" },
};

export default function App() {
  const [view, setView] = useState<View>("coverage");
  const qc = useQueryClient();
  const { data: health } = useHealth();
  const { data: coverage } = useCoverage();
  const nx = useNexRun(() => qc.invalidateQueries({ queryKey: ["coverage"] }));

  // Merge: live run data takes over once a sweep starts; otherwise show the current snapshot.
  const surface = nx.surface.length ? nx.surface : coverage?.surface ?? [];
  const detections = nx.detections.length ? nx.detections : coverage?.detections ?? [];
  const sourcetypes = nx.sourcetypes.length ? nx.sourcetypes : coverage?.sourcetypes ?? [];

  const stats = useMemo(() => {
    const covered = surface.filter((s) => s.covered || s.technique === nx.verified).length;
    const blind = surface.filter((s) => !s.covered && s.technique !== nx.verified).length;
    const eventsAnalyzed = sourcetypes.reduce((n, s) => n + (s.events || 0), 0);
    return { techniques: surface.length, covered, blind, eventsAnalyzed };
  }, [surface, sourcetypes, nx.verified]);

  return (
    <div className="flex min-h-[100dvh] bg-canvas text-body">
      <Sidebar health={health ?? null} view={view} onNavigate={setView} />

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          health={health ?? null}
          running={nx.running}
          title={META[view].title}
          subtitle={META[view].subtitle}
          onRun={nx.run}
          onReset={nx.reopen}
        />

        <main className="mx-auto w-full max-w-[1320px] flex-1 space-y-4 px-6 py-5">
          {view === "coverage" && (
            <>
              <StatBar
                stats={[
                  { label: "Techniques observed", value: stats.techniques },
                  { label: "Covered", value: stats.covered, accent: "secure" },
                  { label: "Blind spots", value: stats.blind, accent: stats.blind ? "blind" : "ink" },
                  { label: "Events analyzed", value: stats.eventsAnalyzed.toLocaleString() },
                ]}
              />
              {nx.gap && <GapAlert gap={nx.gap} verified={!!nx.verified} />}
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                <div className="xl:col-span-2">
                  <CoverageGraph surface={surface} activeTechnique={nx.active} verifiedTechnique={nx.verified} />
                </div>
                <div className="min-h-[360px] xl:col-span-1">
                  <ActivityStream events={nx.events} running={nx.running} />
                </div>
              </div>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                <div className="lg:col-span-1">
                  <EnvironmentPanel sourcetypes={sourcetypes} detections={detections} />
                </div>
                <div className="lg:col-span-2">
                  <DetectionPanel detection={nx.detection} deployed={nx.deployed} />
                </div>
              </div>
            </>
          )}

          {view === "surface" && (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
              <div className="xl:col-span-3">
                <CoverageGraph surface={surface} activeTechnique={nx.active} verifiedTechnique={nx.verified} />
              </div>
              <div className="xl:col-span-2">
                <TechniqueTable surface={surface} verified={nx.verified} active={nx.active} />
              </div>
            </div>
          )}

          {view === "detections" && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <DetectionsTable detections={detections} />
              </div>
              <div className="lg:col-span-1">
                <DetectionPanel detection={nx.detection} deployed={nx.deployed} />
              </div>
            </div>
          )}

          {view === "activity" && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <div className="min-h-[60vh] lg:col-span-2">
                <ActivityStream events={nx.events} running={nx.running} />
              </div>
              <div className="lg:col-span-1">
                <EnvironmentPanel sourcetypes={sourcetypes} detections={detections} />
              </div>
            </div>
          )}

          <footer className="flex items-center justify-between pt-1 text-[11px] text-faint">
            <span>NEX · autonomous purple-team for Splunk</span>
            <span>Splunk · Foundation-Sec-8B · MITRE ATT&amp;CK</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
