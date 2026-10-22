"use client";

// Judi Online watchlist view (v0.16.0 - requirement 18).
// Lensa atas event ber-tag campaign "judi-online" (dipasang enrichment
// GAMBLING_KEYWORDS/GAMBLING_DOMAINS_FILE di pipeline) + alert
// gambling_access. PCAP per sesi tersedia via Arkime SSO (req 13).

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Dice5, ExternalLink, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  getGamblingEvents, getGamblingSummary,
} from "@/lib/ndr/api";
import type { EventDoc, GamblingSummary } from "@/lib/ndr/types";
import { RefreshControls } from "./refresh-controls";
import { StatCard, fmtNumber, fmtTime } from "./shared";

function hostOf(doc: EventDoc): string {
  const s = doc.source as Record<string, Record<string, unknown>>;
  return (s?.dns?.query ?? s?.http?.host ?? s?.tls?.sni ?? "-") as string;
}

export function GamblingView() {
  const { toast } = useToast();
  const [hours, setHours] = useState(24);
  const [summary, setSummary] = useState<GamblingSummary | null>(null);
  const [events, setEvents] = useState<EventDoc[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, e] = await Promise.all([
        getGamblingSummary(hours),
        getGamblingEvents(hours, 100),
      ]);
      setSummary(s);
      setEvents(e.hits ?? []);
      setTotalEvents(e.total ?? 0);
    } catch (err) {
      toast({
        title: "Gagal memuat view Judi Online",
        description: String(err), variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [hours, toast]);

  useEffect(() => { void load(); }, [load]); // eslint-disable-line

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
            <Dice5 className="h-5 w-5 text-rose-400" /> Watchlist Judi Online
          </h2>
          <p className="text-xs text-zinc-500">
            Query network log aktivitas Judi Online (req 18): event
            ber-tag campaign <code className="text-rose-300">
              judi-online
            </code> dari watchlist keyword/domain. Alert perilaku:
            gambling_access. PCAP sesi via Arkime SSO.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="bg-zinc-900 border border-zinc-700 rounded-md
                       text-xs px-2 py-1.5 text-zinc-300"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}>
            {[24, 72, 168, 720].map((h) => (
              <option key={h} value={h}>{h} jam</option>
            ))}
          </select>
          <RefreshControls storageKey="gambling" onRefresh={load}
                           loading={loading} />
        </div>
      </div>

      {loading && !summary ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-20" />)}
        </div>
      ) : summary ? (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard title="Event ter-tag" value={fmtNumber(summary.total_events)}
                      sub={`${hours} jam terakhir`} tone="alert" />
            <StatCard title="Klien teratas"
                      value={summary.top_clients[0]?.key ?? "-"}
                      sub={`${fmtNumber(summary.top_clients[0]?.count ?? 0)} hit`}
                      tone="default" />
            <StatCard title="Domain teratas"
                      value={summary.top_domains[0]?.key ?? "-"}
                      sub={`${fmtNumber(summary.top_domains[0]?.count ?? 0)} hit`}
                      tone="default" />
            <StatCard title="Keyword watchlist"
                      value={String(summary.keywords?.length ?? 0)}
                      sub={(summary.keywords ?? []).slice(0, 4).join(", ")}
                      tone="default" />
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-400 mb-2 flex items-center gap-1">
              <Users className="h-3.5 w-3.5" /> Klien teratas
            </h3>
            <div className="flex flex-wrap gap-2">
              {summary.top_clients.slice(0, 12).map((c) => (
                <Badge key={c.key} variant="outline"
                       className="font-mono text-zinc-300">
                  {c.key} · {fmtNumber(c.count)}
                </Badge>
              ))}
              {summary.top_clients.length === 0 && (
                <span className="text-xs text-zinc-500">
                  Tidak ada aktivitas ter-tag pada rentang ini.
                </span>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-zinc-800 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-zinc-900">
                  <TableHead className="text-zinc-400">Waktu</TableHead>
                  <TableHead className="text-zinc-400">Engine</TableHead>
                  <TableHead className="text-zinc-400">Sumber</TableHead>
                  <TableHead className="text-zinc-400">Host/Domain/SNI</TableHead>
                  <TableHead className="text-zinc-400">Detail</TableHead>
                  <TableHead className="text-zinc-400">PCAP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center
                                                   text-zinc-500 text-sm py-8">
                      Tidak ada event ter-tag pada rentang ini.
                    </TableCell>
                  </TableRow>
                )}
                {events.map((ev) => {
                  const s = ev.source as Record<string, unknown>;
                  const ip = ((s?.source as Record<string, unknown>)
                    ?.ip) as string;
                  const http = s?.http as Record<string, unknown> | undefined;
                  return (
                    <TableRow key={ev.id} className="hover:bg-zinc-900/60">
                      <TableCell className="font-mono text-xs text-zinc-400">
                        {fmtTime(s?.["@timestamp"] as string)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs
                                                       text-zinc-300">
                          {String(s?.source_engine ?? "-")}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{ip}</TableCell>
                      <TableCell className="font-mono text-xs max-w-72
                                           truncate" title={hostOf(ev)}>
                        {hostOf(ev)}
                      </TableCell>
                      <TableCell className="text-xs text-zinc-400">
                        {http
                          ? `${http.method ?? ""} ${http.url ?? ""} `
                            + `${http.status_code ?? ""}`.trim()
                          : (s?.dns as Record<string, unknown>)?.type
                            ? `type ${String((s?.dns as Record<string, unknown>)?.type)}`
                            : "-"}
                      </TableCell>
                      <TableCell>
                        {ip && (
                          <a
                            className="inline-flex items-center gap-1 text-xs
                                       text-sky-400 hover:text-sky-300"
                            href={`/backend/api/arkime/sessions?expression=${
                              encodeURIComponent(
                                `ip == ${ip} || ip == ${ip}`)
                            }&startTime=${Math.floor(
                              (Date.now() - hours * 3_600_000) / 1000,
                            )}&stopTime=${Math.floor(Date.now() / 1000)}`}
                            target="_blank" rel="noreferrer"
                            title="Buka sesi di Arkime viewer (SSO req 13)">
                            <ExternalLink className="h-3 w-3" /> SSO
                          </a>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <p className="text-xs text-zinc-500">{summary.note}</p>
          <Button variant="ghost" size="sm" onClick={() => void load()}>
            Muat ulang
          </Button>
        </>
      ) : null}
    </div>
  );
}
