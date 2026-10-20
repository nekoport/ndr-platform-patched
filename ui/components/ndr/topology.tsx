"use client";

// Topology view - interactive network diagram with animated flows + host drilldown.

import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { NetworkTopology, HostDetailContent } from "./geo";
import { VizPanel } from "./charts";
import { Sparkline } from "./charts";
import { fmtBytes, fmtNumber } from "./shared";
import { useState } from "react";
import type { ExternalEntity, GeoFlow, HostAsset, ZoneTraffic } from "@/lib/ndr/types";
import { cn } from "@/lib/utils";

export function TopologyView({ hosts, flows, externals, zoneTraffic }: {
  hosts: HostAsset[];
  flows: GeoFlow[];
  externals: ExternalEntity[];
  zoneTraffic: ZoneTraffic[];
}) {
  const [selected, setSelected] = useState<HostAsset | null>(null);

  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-5">
        {zoneTraffic.map((z) => (
          <div key={z.zone} className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: z.color }} />
              <span className="text-xs font-medium text-zinc-300">{z.zone}</span>
            </div>
            <div className="mt-1.5 text-lg font-semibold tabular-nums text-zinc-100">
              {z.in_mbps.toFixed(1)} <span className="text-xs font-normal text-zinc-500">Mbps in</span>
            </div>
            <div className="text-[11px] text-zinc-500">{z.hosts} hosts - out {z.out_mbps.toFixed(1)} Mbps</div>
          </div>
        ))}
      </div>

      <VizPanel title="Network topology - sensor vantage" icon={<span className="text-emerald-400">⬡</span>}
                sub="live packet animation is illustrative; edge weights from 24h traffic">
        <NetworkTopology hosts={hosts} selectedIp={selected?.ip ?? null} onSelectHost={setSelected} />
      </VizPanel>

      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto border-zinc-800 bg-zinc-950 sm:max-w-lg">
          {selected && (
            <>
              <SheetHeader className="pb-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={cn(
                    selected.status === "at_risk" ? "border-red-800 bg-red-950/50 text-red-300"
                      : selected.status === "watch" ? "border-amber-800 bg-amber-950/50 text-amber-300"
                      : "border-emerald-800 bg-emerald-950/50 text-emerald-300")}>
                    {selected.status.replace("_", " ")}
                  </Badge>
                  <Badge variant="outline" className="border-zinc-700 text-zinc-400">{selected.zone}</Badge>
                </div>
                <SheetTitle className="text-left text-lg text-zinc-100">
                  {selected.hostname} <span className="font-mono text-sm font-normal text-zinc-500">{selected.ip}</span>
                </SheetTitle>
              </SheetHeader>
              <div className="px-4 pb-8">
                <HostDetailContent host={selected} flows={flows} externals={externals} />
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      <div className="grid gap-4 md:grid-cols-2">
        <VizPanel title="Zone ingress ranking" sub="Mbps, last hour">
          <div className="space-y-3">
            {[...zoneTraffic].sort((a, b) => b.in_mbps - a.in_mbps).map((z) => (
              <div key={z.zone} className="flex items-center gap-3">
                <span className="w-24 shrink-0 text-xs text-zinc-400">{z.zone}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-zinc-800">
                  <div className="h-full rounded-full transition-all duration-700"
                       style={{ width: `${(z.in_mbps / 50) * 100}%`, background: z.color }} />
                </div>
                <span className="w-16 shrink-0 text-right text-xs tabular-nums text-zinc-300">{z.in_mbps.toFixed(1)}</span>
              </div>
            ))}
          </div>
        </VizPanel>
        <VizPanel title="At-risk hosts detail" sub="click to open drilldown">
          <div className="space-y-2">
            {hosts.filter((h) => h.status !== "healthy").map((h) => (
              <button key={h.ip} onClick={() => setSelected(h)}
                      className="flex w-full items-center gap-3 rounded-md border border-zinc-800 bg-zinc-900/50 px-3 py-2 text-left transition-colors hover:bg-zinc-800/60">
                <span className={cn("h-2 w-2 shrink-0 rounded-full",
                  h.status === "at_risk" ? "animate-pulse bg-red-400" : "bg-amber-400")} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-xs font-medium text-zinc-200">{h.hostname} <span className="font-mono text-zinc-600">{h.ip}</span></div>
                  <div className="truncate text-[10px] text-zinc-500">{h.last_alert_title ?? h.role}</div>
                </div>
                <div className="w-20 shrink-0">
                  <Sparkline data={h.traffic_24h} color={h.status === "at_risk" ? "#f87171" : "#fbbf24"} height={22} />
                </div>
                <span className="w-8 shrink-0 text-right text-xs tabular-nums text-zinc-400">{h.risk_score}</span>
              </button>
            ))}
            {!hosts.some((h) => h.status !== "healthy") && (
              <p className="py-6 text-center text-xs text-zinc-600">All hosts healthy</p>
            )}
          </div>
        </VizPanel>
      </div>

      <p className="text-center text-[11px] text-zinc-600">
        Asset inventory & risk scores are derived from observed traffic and detection evidence only - {fmtNumber(hosts.length)} hosts across {zoneTraffic.length} zones,
        {fmtBytes(hosts.reduce((s, h) => s + h.bytes_in + h.bytes_out, 0))} total 24h volume.
      </p>
    </div>
  );
}
