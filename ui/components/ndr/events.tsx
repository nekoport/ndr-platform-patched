"use client";

// Event Search - DSL workbench with facets, result histogram and drilldown.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";

// v0.13.0: rolling default search window (7 days)
function defaultWindowFrom(): string {
  return new Date(Date.now() - 7 * 24 * 3_600_000).toISOString();
}

import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { MiniBar } from "./charts";
import { Paginator, fmtBytes, fmtNumber, fmtTime, JsonViewer, SeverityBadge } from "./shared";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { ChevronsUpDown, Loader2, Play, Search, SlidersHorizontal } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { searchEvents } from "@/lib/ndr/api";
import type { EventDoc, TopItem } from "@/lib/ndr/types";

const DEFAULT_DSL = `{
  "bool": {
    "filter": [
      { "term": { "source.ip": "203.0.113.25" } }
    ]
  }
}`;

const SAMPLES: { label: string; mode: "simple" | "advanced"; value: string }[] = [
  { label: "SQLi source IP", mode: "advanced", value: DEFAULT_DSL },
  { label: "DGA-like domains", mode: "simple", value: "example-dga" },
  { label: "C2 destination", mode: "simple", value: "91.245.77.10" },
  { label: "TLS to C2 host", mode: "advanced", value: `{\n  "bool": {\n    "filter": [\n      { "match_phrase": { "tls.sni": "91-245-77-10" } }\n    ]\n  }\n}` },
  // v0.16.1 (P0-5): preset dulu kirim teks "dns" sebagai term ke field ip
  // -> parsing gagal, SELALU 0 hasil. Kini preset = filter event_type
  // eksplisit (benar target + murah, tanpa wildcard lintas 30jt+ dok).
  { label: "All DNS events", mode: "advanced",
    value: JSON.stringify({ bool: { filter: [{ term: { event_type: "dns" } }] } }, null, 2) },
];

const histConfig = {
  count: { label: "events", color: "#38bdf8" },
} satisfies ChartConfig;

export function EventsView({ canSearch, focus }: {
  canSearch: boolean;
  /** v0.12.1: deep-link from Threat Intel match sheet - filter by event_id.
   *  v0.12.8: alert-detail "Verify in Event Search" - filter by the alert's
   *  source/destination pair inside its own time window. */
  focus?: {
    eventId?: string;
    ips?: { src?: string; dst?: string };
    timeFrom?: string;
    timeTo?: string;
    nonce: number;
  } | null;
}) {
  const { toast } = useToast();
  const [mode, setMode] = useState<"simple" | "advanced">("simple");
  const [index, setIndex] = useState("ndr-events-read");
  const [keyword, setKeyword] = useState("");
  const [dsl, setDsl] = useState(DEFAULT_DSL);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [result, setResult] = useState<{ total: number; hits: EventDoc[]; error?: string; relation?: string } | null>(null);
  const [expanded, setExpanded] = useState<EventDoc | null>(null);
  const [facet, setFacet] = useState<{ field: string; value: string } | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  async function run(overrides?: { mode?: "simple" | "advanced"; query?: string; time_from?: string; time_to?: string; exact_total?: boolean }) {
    if (!canSearch) {
      toast({ title: "Permission denied", description: "Your role cannot run searches.", variant: "destructive" });
      return;
    }
    const m = overrides?.mode ?? mode;
    const q = overrides?.query ?? (m === "advanced" ? dsl : keyword);
    setLoading(true);
    setResult(null);
    setFacet(null);
    try {
      const res = await searchEvents({
        index, mode: m, query: q, size: 80,
        // v0.13.0: default window ROLLS 7 days from now - the old constant
        // (2026-10-05) silently hid ALL events once real time passed it
        time_from: overrides?.time_from ?? defaultWindowFrom(),
        time_to: overrides?.time_to,
        exact_total: overrides?.exact_total ?? false,
      });
      setResult(res);
      setSearched(true);
      setPage(1);
      if (res.error) {
        toast({ title: "Query rejected", description: res.error, variant: "destructive" });
      }
    } catch (e) {
      toast({ title: "Search failed", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  // v0.12.1: deep-link from Threat Intel "Open in Event Search" -
  // switch to advanced mode with an event_id term query and run it.
  useEffect(() => {
    if (focus?.eventId) {
      const q = JSON.stringify(
        { bool: { filter: [{ term: { event_id: focus.eventId } }] } }, null, 2);
      setMode("advanced");
      setDsl(q);
      void run({ mode: "advanced", query: q, time_from: focus.timeFrom });
      return;
    }
    // v0.12.8: verify an alert against its raw events - the query keeps
    // BOTH directions of the observed pair and the alert's own window,
    // so the result set IS the evidence the alert was built from.
    if (focus?.ips) {
      const { src, dst } = focus.ips;
      const clauses: unknown[] = [];
      if (src && dst) {
        clauses.push(
          { bool: { filter: [
            { term: { "source.ip": src } },
            { term: { "destination.ip": dst } },
          ] } },
          { bool: { filter: [
            { term: { "source.ip": dst } },
            { term: { "destination.ip": src } },
          ] } });
      } else {
        const ip = src ?? dst;
        clauses.push(
          { term: { "source.ip": ip } },
          { term: { "destination.ip": ip } });
      }
      const q = JSON.stringify(
        { bool: { filter: [{ bool: { minimum_should_match: 1, should: clauses } }] } },
        null, 2);
      setMode("advanced");
      setDsl(q);
      void run({
        mode: "advanced", query: q,
        time_from: focus.timeFrom, time_to: focus.timeTo,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus?.nonce]);

  const hits = useMemo(() => {
    if (!result?.hits) return [];
    if (!facet) return result.hits;
    return result.hits.filter((h) => {
      const s = h.source as Record<string, unknown>;
      const path = facet.field.split(".");
      let cur: unknown = s;
      for (const p of path) {
        if (cur && typeof cur === "object") cur = (cur as Record<string, unknown>)[p];
        else return false;
      }
      return String(cur ?? "").includes(facet.value);
    });
  }, [result, facet]);

  const pagedHits = useMemo(
    () => hits.slice((page - 1) * pageSize, page * pageSize),
    [hits, page, pageSize]);

  // facets computed from current result set
  const facets = useMemo(() => {
    const collect = (get: (s: EventDoc["source"]) => string | undefined) => {
      const m = new Map<string, number>();
      (result?.hits ?? []).forEach((h) => {
        const v = get(h.source);
        if (v) m.set(v, (m.get(v) ?? 0) + 1);
      });
      return Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8)
        .map(([key, count]): TopItem => ({ key, count }));
    };
    return [
      { title: "source.ip", items: collect((s) => s.source?.ip) },
      { title: "destination.ip", items: collect((s) => s.destination?.ip) },
      { title: "event_type", items: collect((s) => s.event_type ? String(s.event_type) : undefined) },
      { title: "engine", items: collect((s) => s.source_engine ? String(s.source_engine) : undefined) },
      { title: "dns.query", items: collect((s) => s.dns?.query) },
      { title: "tls.sni", items: collect((s) => s.tls?.sni) },
    ].filter((f) => f.items.length > 0);
  }, [result]);

  const histogram = useMemo(() => {
    const m = new Map<string, number>();
    hits.forEach((h) => {
      const t = h.source["@timestamp"];
      if (!t) return;
      const d = new Date(t);
      const bucket = `${String(d.getHours()).padStart(2, "0")}:${String(Math.floor(d.getMinutes() / 10) * 10).padStart(2, "0")}`;
      m.set(bucket, (m.get(bucket) ?? 0) + 1);
    });
    return Array.from(m.entries()).sort().map(([ts, count]) => ({ ts, count }));
  }, [hits]);

  function summary(ev: EventDoc): string {
    const s = ev.source;
    if (s.event_type === "dns") return s.dns?.query ?? "-";
    if (s.event_type === "http") return `${s.http?.method ?? "GET"} ${s.http?.host ?? ""}${s.http?.url ?? ""}`;
    if (s.event_type === "tls") return `SNI ${s.tls?.sni ?? "-"}`;
    if (s.event_type === "alert") return s.alert?.signature ?? "signature alert";
    if (s.event_type === "files") {
      const f = (s as Record<string, unknown>).files as { filename?: string } | undefined;
      return f?.filename ?? "file transfer";
    }
    return `${s.network?.transport ?? "?"} session ${fmtBytes(s.network?.bytes)}`;
  }

  return (
    <div className="space-y-4">
      {/* quick samples */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          <SlidersHorizontal className="h-3 w-3" /> Quick queries
        </span>
        {SAMPLES.map((s) => (
          <button key={s.label}
                  onClick={() => {
                    setMode(s.mode);
                    if (s.mode === "simple") setKeyword(s.value); else setDsl(s.value);
                    run({ mode: s.mode, query: s.value });
                  }}
                  className="rounded-full border border-zinc-800 bg-zinc-900 px-3 py-1 text-[11px] text-zinc-400 transition-colors hover:border-emerald-800 hover:text-emerald-300">
            {s.label}
          </button>
        ))}
      </div>

      <Card className="border-zinc-800 bg-zinc-900/60">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300">Event search</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Tabs value={mode} onValueChange={(v) => setMode(v as "simple" | "advanced")}>
            <TabsList className="bg-zinc-800">
              <TabsTrigger value="simple" className="text-xs">Simple</TabsTrigger>
              <TabsTrigger value="advanced" className="text-xs">Advanced DSL</TabsTrigger>
            </TabsList>
            <TabsContent value="simple" className="mt-3">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-500" />
                <Input value={keyword} onChange={(e) => setKeyword(e.target.value)}
                       onKeyDown={(e) => e.key === "Enter" && run()}
                       placeholder="IP, domain, host, keyword..."
                       className="border-zinc-800 bg-zinc-900 pl-8 text-zinc-200 placeholder:text-zinc-600" />
              </div>
            </TabsContent>
            <TabsContent value="advanced" className="mt-3 space-y-2">
              <Textarea value={dsl} onChange={(e) => setDsl(e.target.value)}
                        spellCheck={false}
                        className="min-h-36 border-zinc-800 bg-zinc-950 font-mono text-xs text-emerald-200/90" />
              <p className="text-[11px] leading-relaxed text-zinc-600">
                Allowed: bool / term / terms / range / match / match_phrase / exists / prefix (no leading wildcard).
                Rejected: script, regexp, fuzzy, wildcard, query_string, nested. Time range is enforced and
                capped at the retention window. Queries are rate-limited and audited.
              </p>
            </TabsContent>
          </Tabs>

          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Select value={index} onValueChange={setIndex}>
              <SelectTrigger className="border-zinc-800 bg-zinc-900 text-xs text-zinc-300 sm:w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
                <SelectItem value="ndr-events-read">ndr-events-read (all)</SelectItem>
                <SelectItem value="ndr-zeek-conn-read">ndr-zeek-conn-read</SelectItem>
                <SelectItem value="ndr-zeek-dns-read">ndr-zeek-dns-read</SelectItem>
                <SelectItem value="ndr-zeek-http-read">ndr-zeek-http-read</SelectItem>
                <SelectItem value="ndr-zeek-tls-read">ndr-zeek-tls-read</SelectItem>
                <SelectItem value="ndr-suricata-read">ndr-suricata-read</SelectItem>
                <SelectItem value="ndr-alerts-read">ndr-alerts-read</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={() => run()} disabled={loading}
                    className="bg-emerald-600 text-white hover:bg-emerald-500">
              {loading ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Play className="mr-1.5 h-4 w-4" />}
              Run query
            </Button>
          </div>
        </CardContent>
      </Card>

      {result && (
        <div className="grid gap-4 lg:grid-cols-4">
          {/* facets */}
          <div className="space-y-3">
            <Card className="border-zinc-800 bg-zinc-900/60">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wider text-zinc-500">
                  <ChevronsUpDown className="h-3.5 w-3.5" /> Facets
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {facets.map((f) => (
                  <div key={f.title}>
                    <div className="mb-1 font-mono text-[10px] text-zinc-500">{f.title}</div>
                    <div className="space-y-1">
                      {f.items.slice(0, 5).map((it) => (
                        <button key={it.key}
                                onClick={() => setFacet(facet?.value === it.key && facet.field === f.title ? null : { field: f.title, value: it.key })}
                                className={`w-full rounded px-1.5 py-0.5 text-left transition-colors ${
                                  facet?.value === it.key ? "bg-emerald-950/60 ring-1 ring-emerald-800" : "hover:bg-zinc-800/60"
                                }`}>
                          <div className="flex justify-between gap-2 text-[11px]">
                            <span className="truncate font-mono text-zinc-300" title={it.key}>{it.key}</span>
                            <span className="shrink-0 tabular-nums text-zinc-500">{it.count}</span>
                          </div>
                          <MiniBar value={it.count} max={f.items[0].count} color="#38bdf8" className="mt-0.5" />
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
                {!facets.length && <p className="py-4 text-center text-xs text-zinc-600">Run a query to see facets</p>}
              </CardContent>
            </Card>
          </div>

          {/* results */}
          <div className="space-y-4 lg:col-span-3">
            {histogram.length > 1 && (
              <Card className="border-zinc-800 bg-zinc-900/60">
                <CardHeader className="pb-1">
                  <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-500">Result distribution by time</CardTitle>
                </CardHeader>
                <CardContent>
                  <ChartContainer config={histConfig} className="h-24 w-full">
                    <BarChart data={histogram} margin={{ top: 0, right: 8, left: -28, bottom: 0 }}>
                      <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                      <XAxis dataKey="ts" tick={{ fill: "#71717a", fontSize: 9 }} stroke="#3f3f46" minTickGap={24} />
                      <YAxis tick={{ fill: "#71717a", fontSize: 9 }} stroke="#3f3f46" allowDecimals={false} />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Bar dataKey="count" fill="#38bdf8" radius={[2, 2, 0, 0]} />
                    </BarChart>
                  </ChartContainer>
                </CardContent>
              </Card>
            )}

            <Card className="border-zinc-800 bg-zinc-900/60">
              <CardHeader className="pb-2">
                <div className="flex flex-wrap items-center gap-2">
                  <CardTitle className="text-sm font-medium text-zinc-300">Results</CardTitle>
                  <Badge variant="outline" className="border-zinc-700 text-zinc-400">
                    {result.error ? "rejected"
                      // v0.16.1 (P2-4): total ter-cap 10.000 dulu tampil
                      // apa adanya (menyesatkan). Kini ada penanda >= dan
                      // tombol hitung total persis.
                      : result.relation === "gte"
                        ? `${fmtNumber(hits.length)} shown / >= ${fmtNumber(result.total)} hits`
                        : `${fmtNumber(hits.length)} shown / ${fmtNumber(result.total)} hits`}
                  </Badge>
                  {!result.error && result.relation === "gte" && (
                    <button onClick={() => void run({ exact_total: true })}
                            className="inline-flex items-center gap-1 rounded-full border border-sky-800 bg-sky-950/40 px-2.5 py-0.5 text-[11px] text-sky-300 hover:border-sky-600">
                      Hitung total persis
                    </button>
                  )}
                  {facet && (
                    <button onClick={() => setFacet(null)}
                            className="inline-flex items-center gap-1 rounded-full border border-emerald-800 bg-emerald-950/50 px-2.5 py-0.5 text-[11px] text-emerald-300">
                      {facet.field}: {facet.value} <span className="ml-1 text-emerald-500">x</span>
                    </button>
                  )}
                </div>
              </CardHeader>
              <CardContent className="p-0">
                {result.error ? (
                  <p className="px-6 py-8 text-center text-sm text-red-400">{result.error}</p>
                ) : !hits.length ? (
                  <p className="px-6 py-8 text-center text-sm text-zinc-500">
                    {searched ? "No events matched." : "Run a query to search events."}
                  </p>
                ) : (
                  <ScrollArea className="max-h-[480px]">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-zinc-800 hover:bg-transparent">
                          <TableHead className="text-zinc-500">Time</TableHead>
                          <TableHead className="text-zinc-500">Engine</TableHead>
                          <TableHead className="text-zinc-500">Type</TableHead>
                          <TableHead className="text-zinc-500">Summary</TableHead>
                          <TableHead className="text-zinc-500">Source</TableHead>
                          <TableHead className="text-zinc-500">Destination</TableHead>
                          <TableHead className="text-zinc-500">Sev</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {pagedHits.map((ev) => (
                          <TableRow key={ev.id}
                                    className="cursor-pointer border-zinc-800/60 hover:bg-zinc-800/40"
                                    onClick={() => setExpanded(ev)}>
                            <TableCell className="whitespace-nowrap text-xs text-zinc-400">{fmtTime(ev.source["@timestamp"])}</TableCell>
                            <TableCell className="text-xs text-zinc-400">{ev.source.source_engine}</TableCell>
                            <TableCell>
                              <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-300">
                                {String(ev.source.event_type)}
                              </Badge>
                            </TableCell>
                            <TableCell className="max-w-[260px] truncate text-sm text-zinc-200">{summary(ev)}</TableCell>
                            <TableCell className="font-mono text-xs text-zinc-400">
                              {ev.source.source?.ip ?? "-"}{ev.source.source?.port ? `:${ev.source.source.port}` : ""}
                            </TableCell>
                            <TableCell className="font-mono text-xs text-zinc-400">
                              {ev.source.destination?.ip ?? "-"}{ev.source.destination?.port ? `:${ev.source.destination.port}` : ""}
                            </TableCell>
                            <TableCell><SeverityBadge severity={ev.source.severity} /></TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                    <Paginator page={page} pageSize={pageSize} total={hits.length}
                               onPage={setPage}
                               onPageSize={(s) => { setPageSize(s); setPage(1); }} />
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      <Sheet open={!!expanded} onOpenChange={(open) => !open && setExpanded(null)}>
        <SheetContent className="w-full overflow-y-auto border-zinc-800 bg-zinc-950 sm:max-w-xl">
          {expanded && (
            <>
              <SheetHeader className="pb-2">
                <SheetTitle className="text-left text-base text-zinc-100">
                  Event <span className="font-mono text-xs text-zinc-500">{expanded.id}</span>
                </SheetTitle>
                <p className="text-xs text-zinc-500">{expanded.index} - {fmtTime(expanded.source["@timestamp"])}</p>
              </SheetHeader>
              <div className="space-y-3 px-4 pb-8">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <KV k="engine" v={String(expanded.source.source_engine ?? "-")} />
                  <KV k="event_type" v={String(expanded.source.event_type ?? "-")} />
                  <KV k="source" v={`${expanded.source.source?.ip ?? "-"}${expanded.source.source?.port ? `:${expanded.source.source.port}` : ""}`} />
                  <KV k="destination" v={`${expanded.source.destination?.ip ?? "-"}${expanded.source.destination?.port ? `:${expanded.source.destination.port}` : ""}`} />
                  <KV k="transport" v={String(expanded.source.network?.transport ?? "-")} />
                  <KV k="bytes" v={fmtBytes(expanded.source.network?.bytes)} />
                </div>
                <JsonViewer data={expanded.source} maxHeight={380} />
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-900/70 px-2.5 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-zinc-600">{k}</div>
      <div className="truncate font-mono text-zinc-300" title={v}>{v}</div>
    </div>
  );
}
