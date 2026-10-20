"use client";

// Threat Intelligence view (Phase 3, doc section 9).
// Feed lifecycle (Update Now / schedule / status), IOC store explorer,
// IOC match stream, and the auditable allowlist workflow.
// Guardrail shown on-page: an IOC match is contextual evidence,
// never automatic proof of compromise.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { RefreshControls } from "./refresh-controls";
import {
  Activity, Ban, BookX, CalendarClock, Database, ExternalLink, FileWarning,
  Filter, Fingerprint, Info, Plus, RefreshCw, Radar, Search, ShieldAlert,
  ShieldCheck, Timer, X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  addTiAllowlist, createTIFeed, getIocActivity, removeTiAllowlist,
  searchAlerts, updateFeedNow, updateTIFeed,
} from "@/lib/ndr/api";
import type {
  AlertDoc, AllowRow, IocActivity, IocMatchRow, IocRow, TIFeed, TIJob,
  ThreatIntelData,
} from "@/lib/ndr/types";
import { DonutChart, HBarList, VizPanel } from "./charts";
import { JsonViewer, StatCard, alertTitle, fmtNumber, fmtTime, timeAgo } from "./shared";

const JOB_STATUS_STYLE: Record<string, string> = {
  success: "bg-emerald-950/70 text-emerald-300 border-emerald-900",
  partial_success: "bg-amber-950/70 text-amber-300 border-amber-900",
  failed: "bg-red-950/70 text-red-300 border-red-900",
  queued: "bg-sky-950/70 text-sky-300 border-sky-900",
  running: "bg-violet-950/70 text-violet-300 border-violet-900",
};

function JobStatusChip({ status }: { status?: string | null }) {
  if (!status) return <span className="text-[11px] text-zinc-600">never run</span>;
  return (
    <Badge variant="outline" className={`text-[10px] ${JOB_STATUS_STYLE[status] ?? "border-zinc-800 text-zinc-400"}`}>
      {status === "running" && <RefreshCw className="mr-1 h-2.5 w-2.5 animate-spin" />}
      {status.replace("_", " ")}
    </Badge>
  );
}

const CONF_STYLE: Record<string, string> = {
  high: "bg-red-950/70 text-red-300 border-red-900",
  medium: "bg-amber-950/70 text-amber-300 border-amber-900",
  low: "bg-zinc-900 text-zinc-400 border-zinc-800",
};

function ConfidenceChip({ level }: { level: string }) {
  return (
    <Badge variant="outline" className={`text-[10px] ${CONF_STYLE[level] ?? CONF_STYLE.low}`}>
      {level}
    </Badge>
  );
}

const TYPE_ICON: Record<string, React.ReactNode> = {
  ip: <Radar className="h-3 w-3" />,
  domain: <BookX className="h-3 w-3" />,
  url: <ExternalLink className="h-3 w-3" />,
  md5: <Fingerprint className="h-3 w-3" />,
  sha1: <Fingerprint className="h-3 w-3" />,
  sha256: <Fingerprint className="h-3 w-3" />,
};

const ADAPTER_LABEL: Record<string, string> = {
  urlhaus: "URLhaus (abuse.ch)",
  threatfox: "ThreatFox (abuse.ch)",
  feodo: "Feodo Tracker (abuse.ch)",
  file: "Local file / fixture",
  stix: "STIX document",
  taxii: "TAXII 2.1 collection",
  misp: "MISP feed",
};

const ADAPTERS: { id: TIFeed["adapter"]; hint: string }[] = [
  { id: "urlhaus", hint: "abuse.ch URLhaus csv_recent" },
  { id: "threatfox", hint: "abuse.ch ThreatFox JSON API" },
  { id: "feodo", hint: "abuse.ch Feodo C2 ipblocklist" },
  { id: "stix", hint: "STIX 2.x bundle JSON / STIX 1.x XML" },
  { id: "taxii", hint: "TAXII 2.1 collection poll (Basic auth in config)" },
  { id: "misp", hint: "MISP feed manifest + event JSON" },
  { id: "file", hint: "local JSONL fixture (offline / PoC)" },
];

// ------------------------------------------------------------- local trend chart
function MatchTrendArea({ data }: { data: { ts: string; count: number }[] }) {
  const W = 560; const H = 130; const PAD = 6;
  const max = Math.max(4, ...data.map((d) => d.count));
  const pts = data.map((d, i) => [
    PAD + (i * (W - 2 * PAD)) / Math.max(1, data.length - 1),
    H - PAD - (d.count / max) * (H - 2 * PAD - 14),
  ] as [number, number]);
  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const area = `${line} L${pts[pts.length - 1]?.[0] ?? W - PAD},${H - 14} L${pts[0]?.[0] ?? PAD},${H - 14} Z`;
  return (
    <div className="w-full">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-[130px] w-full" preserveAspectRatio="none">
        <defs>
          <linearGradient id="ti-trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f87171" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#f87171" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <path d={area} fill="url(#ti-trend-fill)" />
        <path d={line} fill="none" stroke="#f87171" strokeWidth="1.8" strokeLinejoin="round" />
        {pts.map((p, i) => (
          (i % 6 === 0 || i === pts.length - 1) && (
            <circle key={i} cx={p[0]} cy={p[1]} r="2" fill="#f87171" />
          )
        ))}
        <text x={PAD} y={H - 2} className="fill-zinc-600" fontSize="9">-24h</text>
        <text x={W - PAD} y={H - 2} textAnchor="end" className="fill-zinc-600" fontSize="9">now</text>
      </svg>
    </div>
  );
}

// ------------------------------------------------------------------ feed card
function FeedCard({ feed, canAdmin, onUpdated, onUpdate }: {
  feed: TIFeed;
  canAdmin: boolean;
  onUpdated: () => void;
  onUpdate: (id: string) => Promise<unknown>;
}) {
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const running = feed.last_status === "queued" || feed.last_status === "running";
  const ok = feed.enabled && (feed.last_status === "success" || feed.last_status === "partial_success");
  const failed = feed.enabled && feed.last_status === "failed";

  async function toggleEnabled(v: boolean) {
    setBusy(true);
    try {
      await updateTIFeed(feed.id, { enabled: v });
      toast({ title: v ? "Feed enabled" : "Feed disabled", description: feed.name });
      onUpdated();
    } catch (e) {
      toast({ title: "Update failed", description: String(e), variant: "destructive" });
    } finally { setBusy(false); }
  }

  async function handleUpdate() {
    setBusy(true);
    try {
      await onUpdate(feed.id);
      toast({ title: "Update queued", description: `${feed.name} - job picked up by the TI collector` });
      setTimeout(onUpdated, 4000); // let the simulated/real job finish
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      toast({ title: "Update not queued", description: msg, variant: "destructive" });
    } finally { setBusy(false); }
  }

  const job = feed.last_job;
  return (
    <Card className={`border-zinc-800 bg-zinc-900/60 ${failed ? "ring-1 ring-red-900/60" : ""}`}>
      <div className="space-y-2.5 p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Database className={`h-4 w-4 ${ok ? "text-emerald-400" : failed ? "text-red-400" : "text-zinc-500"}`} />
              <span className="truncate text-sm font-medium text-zinc-200">{feed.name}</span>
            </div>
            <div className="mt-0.5 text-[10px] text-zinc-600">{ADAPTER_LABEL[feed.adapter] ?? feed.adapter}</div>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            <JobStatusChip status={feed.last_status} />
            <Switch checked={feed.enabled} onCheckedChange={toggleEnabled}
                    disabled={busy || !canAdmin} className="scale-[0.85]" />
          </div>
        </div>

        <div className="flex items-center gap-3 text-[10px] text-zinc-500">
          <span className="flex items-center gap-1"><CalendarClock className="h-3 w-3" />
            {feed.schedule_min ? `every ${feed.schedule_min}m` : "manual only"}</span>
          <span className="flex items-center gap-1"><Timer className="h-3 w-3" />TTL {feed.ttl_days}d</span>
          <span className="flex items-center gap-1"><Database className="h-3 w-3" />
            {fmtNumber(feed.ioc_count ?? 0)} IOCs</span>
        </div>

        <div className="truncate rounded bg-zinc-950/70 px-2 py-1 font-mono text-[9.5px] text-zinc-500" title={feed.url ?? ""}>
          {feed.url ?? "-"}
        </div>

        <div className="flex items-center justify-between text-[10px] text-zinc-500">
          <span>last success {feed.last_success_at ? timeAgo(feed.last_success_at) : "never"}</span>
          {job && job.status !== "failed" && (
            <span className="text-emerald-400/80">
              +{job.counts.new ?? 0} new / ~{job.counts.changed ?? 0} chg
            </span>
          )}
        </div>

        {job?.error && (
          <div className="rounded border border-red-900/60 bg-red-950/40 px-2 py-1.5 text-[10px] leading-snug text-red-300">
            {job.error}
          </div>
        )}
        {job?.counts?.warnings?.length ? (
          <div className="rounded border border-amber-900/50 bg-amber-950/30 px-2 py-1.5 text-[10px] text-amber-300">
            {job.counts.warnings[0]}
          </div>
        ) : null}

        <Button size="sm" variant="outline"
                className="h-7 w-full border-zinc-800 text-xs text-zinc-300 hover:bg-zinc-800"
                disabled={busy || !canAdmin || running}
                onClick={handleUpdate}>
          <RefreshCw className={`mr-1.5 h-3 w-3 ${running ? "animate-spin" : ""}`} />
          {running ? "Updating..." : "Update now"}
        </Button>
      </div>
    </Card>
  );
}

// ------------------------------------------------------- IOC activity panel
// v0.12.9 - user report: "IOC detail kurang rinci". The detail sheet now
// carries a self-fetching panel that joins the STORE record with what
// actually happened on THIS network (matches, hosts, ioc_match alerts)
// and structured feed provenance - all evidence-backed, nothing inferred.
function IocActivityPanel({ iocValue, onOpenEvent }: {
  iocValue: string;
  onOpenEvent?: (eventId: string, eventTime?: string) => void;
}) {
  const [act, setAct] = useState<IocActivity | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setAct(null);
    getIocActivity(iocValue, 168)
      .then((a) => { if (!cancelled) setAct(a); })
      .catch((e) => { if (!cancelled) setError(String(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [iocValue]);

  return (
    <div className="space-y-2.5">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
        Activity on your network (last 7d)
      </div>
      {loading && (
        <div className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2 text-[11px] text-zinc-500">
          loading IOC activity...
        </div>
      )}
      {!loading && error && (
        <div className="rounded border border-red-900/60 bg-red-950/30 px-2.5 py-2 text-[11px] text-red-300">
          activity lookup failed: {error}
        </div>
      )}
      {!loading && !error && act && (
        <>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
              <div className="text-[9.5px] uppercase tracking-wide text-zinc-600">matches</div>
              <div className="mt-0.5 font-mono text-sm text-zinc-100">{act.activity.matches_total}</div>
            </div>
            <div className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
              <div className="text-[9.5px] uppercase tracking-wide text-zinc-600">unique hosts</div>
              <div className="mt-0.5 font-mono text-sm text-zinc-100">{act.activity.unique_source_hosts}</div>
            </div>
            <div className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
              <div className="text-[9.5px] uppercase tracking-wide text-zinc-600">last match</div>
              <div className="mt-0.5 font-mono text-[11px] text-zinc-300">
                {act.activity.last_match ? fmtTime(act.activity.last_match) : "-"}
              </div>
            </div>
          </div>

          {act.activity.matches_total === 0 ? (
            <p className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2 text-[11px] leading-relaxed text-zinc-500">
              No traffic on your network touched this IOC in the window.
              A match needs BOTH an active IOC from an enabled feed AND
              traffic that actually contacts it - low activity usually
              means narrow IOC coverage, not that the indicator is gone.
            </p>
          ) : (
            <>
              {act.activity.top_source_hosts.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {act.activity.top_source_hosts.map((h) => (
                    <Badge key={h.key} variant="outline"
                           className="border-zinc-800 bg-zinc-900 font-mono text-[10px] text-zinc-300">
                      {h.key} ({h.count})
                    </Badge>
                  ))}
                </div>
              )}
              <div className="space-y-1">
                {act.recent_matches.slice(0, 5).map((m) => (
                  <div key={m.id}
                       className="flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-1.5 text-[11px]">
                    <span className="shrink-0 font-mono text-zinc-500">{fmtTime(m["@timestamp"])}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-zinc-300">
                      {m.source_ip ?? "-"}{m.match_field ? ` on ${m.match_field}` : ""}
                    </span>
                    {onOpenEvent && m.event_id && (
                      <button className="shrink-0 text-[10px] text-sky-400 hover:text-sky-300"
                              onClick={() => onOpenEvent(m.event_id, m["@timestamp"])}>
                        open event
                      </button>
                    )}
                  </div>
                ))}
              </div>
              {act.related_alerts.items.length > 0 && (
                <div>
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
                    related ioc_match alerts ({act.related_alerts.total})
                  </div>
                  <div className="space-y-1.5">
                    {act.related_alerts.items.slice(0, 5).map((a) => (
                      <div key={a.alert_id}
                           className="flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-1.5">
                        <Badge variant="outline" className={`shrink-0 text-[9px] ${a.severity === "critical" || a.severity === "high"
                          ? "border-red-900 bg-red-950/50 text-red-300"
                          : a.severity === "medium"
                            ? "border-amber-900 bg-amber-950/50 text-amber-300"
                            : "border-zinc-800 text-zinc-400"}`}>
                          {a.severity}
                        </Badge>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-[11px] text-zinc-300">{alertTitle(a.title)}</div>
                          <div className="text-[9.5px] text-zinc-600">{timeAgo(a.last_seen)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

// Structured provenance feed entries (v0.12.9) - falls back to the
// caller-provided node when the activity lookup has not returned yet.
function IocProvenance({ iocValue, fallback }: {
  iocValue: string;
  fallback: React.ReactNode;
}) {
  const [act, setAct] = useState<IocActivity | null>(null);
  useEffect(() => {
    let cancelled = false;
    getIocActivity(iocValue, 168)
      .then((a) => { if (!cancelled) setAct(a); })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [iocValue]);

  const prov = act?.ioc.provenance ?? [];
  if (!prov.length) return <>{fallback}</>;
  return (
    <div className="space-y-1.5">
      {prov.map((p, i) => (
        <div key={`${p.feed}-${i}`}
             className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="min-w-0 truncate text-xs font-medium text-zinc-200">{p.feed}</span>
            <ConfidenceChip level={p.confidence ?? "low"} />
          </div>
          <div className="mt-1 flex flex-wrap gap-x-3 text-[10px] text-zinc-500">
            <span>first seen {p.first_seen ? timeAgo(p.first_seen) : "-"}</span>
            <span>last seen {p.last_seen ? timeAgo(p.last_seen) : "-"}</span>
            {p.malware && <span>family: {p.malware}</span>}
          </div>
          {p.reference && (
            <a href={p.reference} target="_blank" rel="noreferrer"
               className="mt-0.5 block truncate font-mono text-[10px] text-sky-400 hover:text-sky-300">
              {p.reference}
            </a>
          )}
        </div>
      ))}
      <details className="text-[10px] text-zinc-600">
        <summary className="cursor-pointer select-none">raw record</summary>
        <JsonViewer data={act?.ioc ?? null} maxHeight={160} />
      </details>
    </div>
  );
}

// ------------------------------------------------------------------ main view
export function ThreatIntelView({ data, loading, canAdmin, onRefresh, section = "results", onOpenEvent }: {
  data: ThreatIntelData | null;
  loading: boolean;
  canAdmin: boolean;
  onRefresh: () => void;
  /** "results" = IOC matches & store (Detect menu); "feeds" = feed management (Configuration menu). */
  section?: "results" | "feeds";
  /** v0.12.1: jump to Event Search filtered by the matched event id. */
  onOpenEvent?: (eventId: string, eventTime?: string) => void;
}) {
  const { toast } = useToast();
  const [tab, setTab] = useState("matches");
  const [feedTab, setFeedTab] = useState("jobs");
  const [iocType, setIocType] = useState("all");
  const [iocStatus, setIocStatus] = useState("active");
  const [iocQuery, setIocQuery] = useState("");
  const [matchDetail, setMatchDetail] = useState<IocMatchRow | null>(null);
  const [iocDetail, setIocDetail] = useState<IocRow | null>(null);
  // v0.12.1: related alerts for the host behind the selected match
  const [related, setRelated] = useState<AlertDoc[] | null>(null);
  const [relatedLoading, setRelatedLoading] = useState(false);
  const [allowDialog, setAllowDialog] = useState(false);
  const [allowDraft, setAllowDraft] = useState<{ type: string; value: string; reason: string }>(
    { type: "ip", value: "", reason: "" });
  const [allowBusy, setAllowBusy] = useState(false);

  // v0.12.1: when a match sheet opens, pull recent alerts that share the
  // host (source.ip preferred, fallback destination.ip). Read-only view.
  const host = matchDetail?.source_ip ?? matchDetail?.destination_ip ?? null;
  useEffect(() => {
    if (!matchDetail) { setRelated(null); return; }
    // v0.13.0: no host -> NO search. The old fallback (keyword "") listed
    // the 6 NEWEST alerts as fake "related" results.
    if (!host) { setRelated([]); setRelatedLoading(false); return; }
    let cancelled = false;
    setRelatedLoading(true);
    setRelated(null);
    searchAlerts({ keyword: host, size: 6 })
      .then((res) => { if (!cancelled) setRelated(res.hits); })
      .catch(() => { if (!cancelled) setRelated(null); })
      .finally(() => { if (!cancelled) setRelatedLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [matchDetail?.id]);

  // ----------------------------- new feed dialog (v0.11)
  const [feedDialog, setFeedDialog] = useState(false);
  const [feedBusy, setFeedBusy] = useState(false);
  const [feedDraft, setFeedDraft] = useState<{
    name: string; adapter: TIFeed["adapter"]; url: string;
    schedule_min: string; ttl_days: string; enabled: boolean; config: string;
  }>({ name: "", adapter: "urlhaus", url: "", schedule_min: "120",
       ttl_days: "14", enabled: false, config: "{}" });

  async function submitFeed() {
    const name = feedDraft.name.trim();
    if (!name || name.length < 2) {
      toast({ title: "Missing fields", description: "feed name is required (min 2 chars)", variant: "destructive" });
      return;
    }
    let config: Record<string, unknown> = {};
    if (feedDraft.config.trim() && feedDraft.config.trim() !== "{}") {
      try {
        config = JSON.parse(feedDraft.config);
      } catch {
        toast({ title: "Invalid config", description: "config must be valid JSON", variant: "destructive" });
        return;
      }
    }
    setFeedBusy(true);
    try {
      await createTIFeed({
        name, adapter: feedDraft.adapter,
        url: feedDraft.url.trim() || null,
        enabled: feedDraft.enabled,
        schedule_min: Number(feedDraft.schedule_min) || 0,
        ttl_days: Number(feedDraft.ttl_days) || 14,
        config,
      });
      toast({ title: "Feed created", description: `${name} - enable it and run Update Now to fetch` });
      setFeedDialog(false);
      setFeedDraft({ name: "", adapter: "urlhaus", url: "", schedule_min: "120",
                     ttl_days: "14", enabled: false, config: "{}" });
      onRefresh();
    } catch (e) {
      toast({ title: "Create failed", description: String(e), variant: "destructive" });
    } finally { setFeedBusy(false); }
  }

  const filteredIocs = useMemo(() => {
    if (!data) return [];
    return data.iocs.items.filter((i) => {
      if (iocType !== "all" && i.ioc_type !== iocType) return false;
      if (iocStatus !== "all" && i.status !== iocStatus) return false;
      if (iocQuery) {
        const kw = iocQuery.toLowerCase();
        if (!`${i.ioc_value} ${i.malware ?? ""}`.toLowerCase().includes(kw)) return false;
      }
      return true;
    });
  }, [data, iocType, iocStatus, iocQuery]);

  const typeDonut = useMemo(() => {
    if (!data) return [];
    const colors: Record<string, string> = {
      ip: "#f87171", domain: "#fbbf24", url: "#a78bfa",
      md5: "#38bdf8", sha1: "#38bdf8", sha256: "#818cf8",
    };
    return Object.entries(data.overview.by_type_active).map(([name, value]) => ({
      name, value: Number(value) || 0, color: colors[name] ?? "#71717a",
    }));
  }, [data]);

  const malwareBars = useMemo(() => {
    if (!data) return [];
    return Object.entries(data.overview.matches_by_source)
      .sort((a, b) => Number(b[1]) - Number(a[1])).slice(0, 8)
      .map(([key, count]) => ({ key, count: Number(count) || 0 }));
  }, [data]);

  // v0.12.9: starter feeds ship DISABLED - with zero enabled feeds there
  // are zero active IOCs and zero matches, which users legitimately read
  // as "broken". Offer a one-click enable + update for the public
  // abuse.ch starters (ti_admin only).
  const disabledStarters = useMemo(
    () => (data?.feeds ?? []).filter(
      (f) => !f.enabled && ["feodo", "urlhaus", "threatfox"].includes(f.adapter)),
    [data]);
  const [enablingFeed, setEnablingFeed] = useState<string | null>(null);

  async function enableStarterFeed(feed: TIFeed) {
    setEnablingFeed(feed.id);
    try {
      await updateTIFeed(feed.id, { enabled: true });
      try { await updateFeedNow(feed.id); } catch { /* job may already run */ }
      toast({
        title: "Feed enabled + update queued",
        description: `${feed.name} - the pipeline TI collector fetches the IOCs; the matcher picks them up within 60s.`,
      });
      onRefresh();
    } catch (e) {
      toast({ title: "Enable failed", description: String(e), variant: "destructive" });
    } finally {
      setEnablingFeed(null);
    }
  }

  async function handleAllowAdd() {
    if (!allowDraft.value || allowDraft.reason.length < 3) {
      toast({ title: "Missing fields", description: "IOC value and a reason (min 3 chars) are required", variant: "destructive" });
      return;
    }
    setAllowBusy(true);
    try {
      await addTiAllowlist({
        ioc_type: allowDraft.type as AllowRow["ioc_type"],
        ioc_value: allowDraft.value.trim().toLowerCase(),
        reason: allowDraft.reason.trim(),
      });
      toast({ title: "Allowlisted", description: `${allowDraft.type}: ${allowDraft.value} - matches will be suppressed after matcher reload` });
      setAllowDialog(false);
      setAllowDraft({ type: "ip", value: "", reason: "" });
      onRefresh();
    } catch (e) {
      toast({ title: "Failed to add", description: String(e), variant: "destructive" });
    } finally { setAllowBusy(false); }
  }

  async function handleAllowRemove(id: number) {
    try {
      await removeTiAllowlist(id);
      toast({ title: "Entry removed" });
      onRefresh();
    } catch (e) {
      toast({ title: "Failed to remove", description: String(e), variant: "destructive" });
    }
  }

  if (loading || !data) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-24 bg-zinc-900" />)}
        </div>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-56 bg-zinc-900" />)}
        </div>
      </div>
    );
  }

  const ov = data.overview;

  // ============================ FEEDS (management - Configuration menu) ====
  if (section === "feeds") {
    return (
      <div className="space-y-4">
        <div className="flex items-start gap-2.5 rounded-lg border border-sky-900/50 bg-sky-950/25 px-3.5 py-2.5">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
          <p className="text-xs leading-relaxed text-sky-200/90">
            <span className="font-semibold">Threat feed management.</span> This view manages
            the SOURCES of threat intelligence (feeds, update jobs, IOC allowlist).
            Detection RESULTS from these feeds (IOC matches on your traffic) live in
            Detect &rarr; Threat Intel. Failed feed updates never remove valid IOCs
            (design doc section 9.2).
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <StatCard title="Feeds total" value={fmtNumber(ov.feeds_total)} sub="configured sources" />
          <StatCard title="Feeds enabled" value={`${ov.feeds_enabled}/${ov.feeds_total}`}
                    sub={ov.feeds_degraded ? `${ov.feeds_degraded} degraded` : "all healthy"}
                    tone={ov.feeds_degraded ? "alert" : "ok"} />
          <StatCard title="Active IOCs" value={fmtNumber(ov.iocs_active)}
                    sub={`${fmtNumber(ov.iocs_expiring_3d)} expiring in 3d`} />
          <StatCard title="Update jobs shown" value={fmtNumber(data.jobs.length)}
                    sub="latest collector runs" />
        </div>

        {/* feed cards */}
        <div>
          <div className="mb-2 flex items-center justify-between">
            <h3 className="flex items-center gap-2 text-sm font-medium text-zinc-300">
              <RefreshCw className="h-4 w-4 text-emerald-400" /> Threat feeds
              <span className="text-[11px] font-normal text-zinc-600">- Update Now queues a job; the pipeline TI collector runs it</span>
            </h3>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="ghost" onClick={onRefresh}
                      className="h-7 text-[11px] text-zinc-400 hover:bg-zinc-800">
                <RefreshCw className="mr-1 h-3 w-3" /> Refresh
              </Button>
              <Button size="sm" disabled={!canAdmin} onClick={() => setFeedDialog(true)}
                      className="h-7 bg-emerald-900/60 text-[11px] text-emerald-200 hover:bg-emerald-900">
                <Plus className="mr-1 h-3 w-3" /> Add feed
              </Button>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {data.feeds.map((f) => (
              <FeedCard key={f.id} feed={f} canAdmin={canAdmin} onUpdated={onRefresh}
                        onUpdate={updateFeedNow} />
            ))}
          </div>
        </div>

        {/* tabs: jobs / allowlist */}
        <Tabs value={feedTab} onValueChange={setFeedTab}>
          <TabsList className="bg-zinc-800">
            <TabsTrigger value="jobs" className="text-xs">
              <FileWarning className="mr-1.5 h-3 w-3" /> Update jobs ({data.jobs.length})
            </TabsTrigger>
            <TabsTrigger value="allowlist" className="text-xs">
              <Ban className="mr-1.5 h-3 w-3" /> Allowlist ({data.allowlist.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="jobs">
            <Card className="border-zinc-800 bg-zinc-900/60">
              <ScrollArea className="max-h-[430px]">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800">
                      <TableHead className="text-zinc-400">Queued</TableHead>
                      <TableHead className="text-zinc-400">Feed</TableHead>
                      <TableHead className="text-zinc-400">Trigger</TableHead>
                      <TableHead className="text-zinc-400">Status</TableHead>
                      <TableHead className="text-zinc-400">New</TableHead>
                      <TableHead className="text-zinc-400">Changed</TableHead>
                      <TableHead className="text-zinc-400">Unchanged</TableHead>
                      <TableHead className="text-zinc-400">Expired</TableHead>
                      <TableHead className="text-zinc-400">Detail</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.jobs.map((j) => (
                      <TableRow key={j.id} className="border-zinc-800/70">
                        <TableCell className="whitespace-nowrap font-mono text-[11px] text-zinc-400">{fmtTime(j.created_at)}</TableCell>
                        <TableCell className="text-xs text-zinc-200">{j.feed_name ?? "-"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px] border-zinc-800 text-zinc-400">
                            {j.trigger}{j.trigger === "manual" && j.created_by ? ` (${j.created_by})` : ""}
                          </Badge>
                        </TableCell>
                        <TableCell><JobStatusChip status={j.status} /></TableCell>
                        <TableCell className="text-xs text-emerald-300">{j.counts.new ?? "-"}</TableCell>
                        <TableCell className="text-xs text-amber-300">{j.counts.changed ?? "-"}</TableCell>
                        <TableCell className="text-xs text-zinc-400">{j.counts.unchanged ?? "-"}</TableCell>
                        <TableCell className="text-xs text-zinc-400">{j.counts.expired_total ?? "-"}</TableCell>
                        <TableCell className="max-w-[220px]">
                          {j.error
                            ? <span className="line-clamp-2 text-[10px] text-red-300">{j.error}</span>
                            : j.counts.warnings?.length
                              ? <span className="line-clamp-2 text-[10px] text-amber-300">{j.counts.warnings[0]}</span>
                              : <span className="text-[10px] text-zinc-600">ok</span>}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>
            </Card>
          </TabsContent>

          <TabsContent value="allowlist">
            <Card className="border-zinc-800 bg-zinc-900/60 p-3">
              <div className="mb-3 flex items-center justify-between">
                <p className="text-[11px] text-zinc-500">
                  Allowlisted indicators are suppressed by the matcher. Every change is audited (doc 9.2 step 10).
                </p>
                <Button size="sm" className="h-7 bg-emerald-900/60 text-[11px] text-emerald-200 hover:bg-emerald-900"
                        disabled={!canAdmin}
                        onClick={() => setAllowDialog(true)}>
                  <Ban className="mr-1 h-3 w-3" /> Add allowlist entry
                </Button>
              </div>
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800">
                    <TableHead className="text-zinc-400">Type</TableHead>
                    <TableHead className="text-zinc-400">Value</TableHead>
                    <TableHead className="text-zinc-400">Reason</TableHead>
                    <TableHead className="text-zinc-400">By</TableHead>
                    <TableHead className="text-zinc-400">Added</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.allowlist.map((a) => (
                    <TableRow key={a.id} className="border-zinc-800/70">
                      <TableCell><Badge variant="outline" className="text-[10px] border-zinc-800 text-zinc-400">{a.ioc_type}</Badge></TableCell>
                      <TableCell className="max-w-[220px] truncate font-mono text-xs text-zinc-200">{a.ioc_value}</TableCell>
                      <TableCell className="max-w-[320px] text-xs text-zinc-400">{a.reason}</TableCell>
                      <TableCell className="text-xs text-zinc-400">{a.created_by ?? "-"}</TableCell>
                      <TableCell className="whitespace-nowrap text-[11px] text-zinc-500">{timeAgo(a.created_at)}</TableCell>
                      <TableCell>
                        <Button size="icon" variant="ghost"
                                className="h-6 w-6 text-zinc-500 hover:bg-red-950/60 hover:text-red-300"
                                disabled={!canAdmin} title="Remove"
                                onClick={() => handleAllowRemove(a.id)}>
                          <X className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {!data.allowlist.length && (
                    <TableRow><TableCell colSpan={6} className="py-8 text-center text-xs text-zinc-600">
                      Allowlist is empty - verified false positives can be suppressed here.
                    </TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </Card>
          </TabsContent>
        </Tabs>

        {/* allowlist add dialog */}
        <Dialog open={allowDialog} onOpenChange={setAllowDialog}>
          <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-sm text-zinc-200">
                <Ban className="h-4 w-4 text-amber-400" /> Add allowlist entry
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-3 py-1">
              <p className="text-[11px] leading-relaxed text-zinc-500">
                Use this workflow for verified false positives (doc 9.2 step 10). The reason is mandatory
                and the change is written to the audit log.
              </p>
              <div className="grid grid-cols-[130px_1fr] gap-2">
                <Select value={allowDraft.type}
                        onValueChange={(v) => setAllowDraft((d) => ({ ...d, type: v }))}>
                  <SelectTrigger className="h-8 border-zinc-800 bg-zinc-950 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-950">
                    {["ip", "domain", "url", "md5", "sha1", "sha256"].map((t) => (
                      <SelectItem key={t} value={t}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input value={allowDraft.value}
                       onChange={(e) => setAllowDraft((d) => ({ ...d, value: e.target.value }))}
                       placeholder="indicator value"
                       className="h-8 border-zinc-800 bg-zinc-950 font-mono text-xs" />
              </div>
              <Input value={allowDraft.reason}
                     onChange={(e) => setAllowDraft((d) => ({ ...d, reason: e.target.value }))}
                     placeholder="reason - e.g. verified internal lab host (ticket #)"
                     className="h-8 border-zinc-800 bg-zinc-950 text-xs" />
            </div>
            <DialogFooter>
              <Button size="sm" variant="ghost" onClick={() => setAllowDialog(false)}
                      className="h-8 text-xs text-zinc-400">Cancel</Button>
              <Button size="sm" onClick={handleAllowAdd} disabled={allowBusy}
                      className="h-8 bg-emerald-900/60 text-xs text-emerald-200 hover:bg-emerald-900">
                <ShieldCheck className="mr-1 h-3.5 w-3.5" /> {allowBusy ? "Saving..." : "Allowlist"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* add feed dialog (v0.11) */}
        <Dialog open={feedDialog} onOpenChange={(open) => { if (!open) setFeedDialog(false); }}>
          <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-sm text-zinc-200">
                <Plus className="h-4 w-4 text-emerald-400" /> Add threat feed
              </DialogTitle>
            </DialogHeader>
            <div className="grid gap-3 py-1">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="feed-name">Feed name</Label>
                  <Input id="feed-name" value={feedDraft.name}
                         placeholder="partner-stix"
                         onChange={(e) => setFeedDraft((d) => ({ ...d, name: e.target.value }))}
                         className="h-8 border-zinc-800 bg-zinc-900 text-xs" />
                </div>
                <div className="space-y-1.5">
                  <Label>Adapter / format</Label>
                  <Select value={feedDraft.adapter}
                          onValueChange={(v) => setFeedDraft((d) => ({ ...d, adapter: v as TIFeed["adapter"] }))}>
                    <SelectTrigger className="h-8 border-zinc-800 bg-zinc-900 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent className="border-zinc-800 bg-zinc-900">
                      {ADAPTERS.map((a) => (
                        <SelectItem key={a.id} value={a.id} className="text-xs">
                          {ADAPTER_LABEL[a.id] ?? a.id}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-[10px] text-zinc-600">
                    {ADAPTERS.find((a) => a.id === feedDraft.adapter)?.hint}
                  </p>
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="feed-url">URL (feed source)</Label>
                <Input id="feed-url" value={feedDraft.url}
                       placeholder="https://taxii.example.csirt/discovery"
                       onChange={(e) => setFeedDraft((d) => ({ ...d, url: e.target.value }))}
                       className="h-8 border-zinc-800 bg-zinc-900 font-mono text-xs" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="feed-sched">Schedule (minutes, 0 = manual)</Label>
                  <Input id="feed-sched" type="number" min={0} max={10080}
                         value={feedDraft.schedule_min}
                         onChange={(e) => setFeedDraft((d) => ({ ...d, schedule_min: e.target.value }))}
                         className="h-8 border-zinc-800 bg-zinc-900 text-xs" />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="feed-ttl">IOC TTL (days)</Label>
                  <Input id="feed-ttl" type="number" min={1} max={365}
                         value={feedDraft.ttl_days}
                         onChange={(e) => setFeedDraft((d) => ({ ...d, ttl_days: e.target.value }))}
                         className="h-8 border-zinc-800 bg-zinc-900 text-xs" />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="feed-config">Config JSON (credentials, options)</Label>
                <Textarea id="feed-config" value={feedDraft.config} spellCheck={false}
                          placeholder='{"username":"svc","password":"...","collection_id":"iocs"}'
                          onChange={(e) => setFeedDraft((d) => ({ ...d, config: e.target.value }))}
                          className="min-h-16 border-zinc-800 bg-zinc-900 font-mono text-[11px]" />
                <p className="text-[10px] text-zinc-600">
                  taxii: username / password / collection_id / limit · misp: max_events ·
                  threatfox: days · secrets are masked on every read and never logged.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Switch id="feed-enabled" checked={feedDraft.enabled}
                        onCheckedChange={(v) => setFeedDraft((d) => ({ ...d, enabled: v }))} />
                <Label htmlFor="feed-enabled" className="text-xs text-zinc-400">
                  Enable immediately
                </Label>
              </div>
            </div>
            <DialogFooter>
              <Button size="sm" variant="ghost" onClick={() => setFeedDialog(false)}
                      className="h-8 text-xs text-zinc-400">Cancel</Button>
              <Button size="sm" onClick={() => void submitFeed()} disabled={feedBusy}
                      className="h-8 bg-emerald-900/60 text-xs text-emerald-200 hover:bg-emerald-900">
                {feedBusy ? "Creating..." : "Create feed"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  // ============================ RESULTS (detection - Detect menu) ==========
  return (
    <div className="space-y-4">
      {/* v0.14.0: in-page refresh + selectable auto-refresh (re-runs the
          whole TI bundle: overview + feeds + jobs + IOCs + matches) */}
      <div className="flex justify-end">
        <RefreshControls storageKey="threatintel" onRefresh={onRefresh} loading={loading} />
      </div>
      {/* disclaimer - doc 9.2 guardrail */}
      <div className="flex items-start gap-2.5 rounded-lg border border-amber-900/50 bg-amber-950/25 px-3.5 py-2.5">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
        <p className="text-xs leading-relaxed text-amber-200/90">
          <span className="font-semibold">IOC matches are contextual evidence, not automatic proof of compromise.</span>{" "}
          Indicators come from external feeds with an expiry policy; every sighting still requires analyst verification
          before any response action (design doc section 9.2). Failed feed updates never remove valid IOCs.
        </p>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <StatCard title="Active IOCs" value={fmtNumber(ov.iocs_active)}
                  sub={`${fmtNumber(ov.iocs_expired)} expired (marked, kept)`}
                  tone="ok" />
        <StatCard title="Matches 24h" value={fmtNumber(ov.matches_24h)}
                  sub="events touching known IOCs" tone="alert" />
        <StatCard title="Feeds enabled" value={`${ov.feeds_enabled}/${ov.feeds_total}`}
                  sub={ov.feeds_degraded ? `${ov.feeds_degraded} degraded` : "all healthy"}
                  tone={ov.feeds_degraded ? "alert" : "ok"} />
        <StatCard title="Expiring 3d" value={fmtNumber(ov.iocs_expiring_3d)}
                  sub="need feed refresh" tone="alert" />
        <StatCard title="IOC types" value={Object.keys(ov.by_type_active).length}
                  sub="ip / domain / url / hash" />
        <StatCard title="Match families" value={Object.keys(ov.matches_by_source).length}
                  sub="distinct malware labels" />
      </div>

      {/* v0.12.9: "why so few matches" coverage explainer + one-click
          enable for the public abuse.ch starter feeds (they ship DISABLED
          by design - with no enabled feed there are no IOCs to match). */}
      {(ov.feeds_enabled === 0 || ov.iocs_active < 50) && (
        <div className="flex items-start gap-2.5 rounded-lg border border-sky-900/50 bg-sky-950/25 px-3.5 py-2.5">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
          <div className="flex-1 space-y-2 text-xs leading-relaxed text-sky-200/90">
            <p>
              <span className="font-semibold">Why so few IOC matches?</span>{" "}
              Matching uses ONLY indicators from feeds that are ENABLED and
              successfully synced (starter feeds ship disabled). A match
              fires when your traffic actually contacts an active IOC -
              few matches usually mean narrow IOC coverage, not a broken
              pipeline. Enable the public abuse.ch starters below (or add
              partner feeds in Configuration &rarr; Intel Feeds), then run
              "Update now"; the matcher reloads within 60 seconds.
            </p>
            {canAdmin && disabledStarters.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {disabledStarters.map((f) => (
                  <Button key={f.id} size="sm" variant="outline"
                          className="h-7 border-sky-800 bg-sky-950/40 text-[11px] text-sky-200 hover:bg-sky-900/60"
                          disabled={enablingFeed === f.id}
                          onClick={() => void enableStarterFeed(f)}>
                    <RefreshCw className={`mr-1.5 h-3 w-3 ${enablingFeed === f.id ? "animate-spin" : ""}`} />
                    Enable + update: {f.name}
                  </Button>
                ))}
              </div>
            )}
            {!canAdmin && disabledStarters.length > 0 && (
              <p className="text-[11px] text-sky-300/70">
                {disabledStarters.length} starter feed(s) are still disabled -
                ask an administrator (feed management permission) to enable them.
              </p>
            )}
          </div>
        </div>
      )}

      {/* charts row */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <VizPanel title="IOC match trend (24h)" icon={<Activity className="h-4 w-4 text-red-400" />}
                  sub="hourly bucket of event-to-IOC matches">
          <MatchTrendArea data={data.match_trend} />
        </VizPanel>
        <VizPanel title="Active IOC mix" icon={<Database className="h-4 w-4 text-sky-400" />}
                  sub="by indicator type">
          <DonutChart data={typeDonut} centerValue={fmtNumber(ov.iocs_active)} centerLabel="active" height={168} />
        </VizPanel>
        <VizPanel title="Matches by family" icon={<ShieldAlert className="h-4 w-4 text-violet-400" />}
                  sub="malware label attached to matched IOCs">
          <HBarList items={malwareBars} color="#a78bfa" />
        </VizPanel>
      </div>

      <p className="text-[11px] text-zinc-600">
        Feed sources, update jobs and the IOC allowlist are managed separately in
        Configuration &rarr; Intel Feeds.
      </p>

      {/* tabs: matches / iocs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-zinc-800">
          <TabsTrigger value="matches" className="text-xs">
            <Radar className="mr-1.5 h-3 w-3" /> Matches ({data.matches.total})
          </TabsTrigger>
          <TabsTrigger value="iocs" className="text-xs">
            <Database className="mr-1.5 h-3 w-3" /> IOC store ({data.iocs.total})
          </TabsTrigger>
        </TabsList>

        {/* -------- matches -------- */}
        <TabsContent value="matches">
          <Card className="border-zinc-800 bg-zinc-900/60">
            <ScrollArea className="max-h-[430px]">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800">
                    <TableHead className="text-zinc-400">Time</TableHead>
                    <TableHead className="text-zinc-400">IOC</TableHead>
                    <TableHead className="text-zinc-400">Family</TableHead>
                    <TableHead className="text-zinc-400">Confidence</TableHead>
                    <TableHead className="text-zinc-400">Source host</TableHead>
                    <TableHead className="text-zinc-400">Matched on</TableHead>
                    <TableHead className="text-zinc-400">Zone</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.matches.hits.map((m) => (
                    <TableRow key={m.id}
                              className="cursor-pointer border-zinc-800/70 hover:bg-zinc-800/40"
                              onClick={() => setMatchDetail(m)}>
                      <TableCell className="whitespace-nowrap font-mono text-[11px] text-zinc-400">
                        {fmtTime(m["@timestamp"])}
                      </TableCell>
                      <TableCell className="max-w-[240px]">
                        <div className="flex items-center gap-1.5">
                          {TYPE_ICON[m.ioc_type]}
                          <span className="truncate font-mono text-xs text-zinc-200">{m.ioc_value}</span>
                        </div>
                        <div className="text-[9.5px] uppercase tracking-wide text-zinc-600">{m.ioc_type}</div>
                      </TableCell>
                      <TableCell className="text-xs text-zinc-300">{m.ioc_source}</TableCell>
                      <TableCell><ConfidenceChip level={m.ioc_confidence} /></TableCell>
                      <TableCell className="font-mono text-xs text-zinc-300">{m.source_ip ?? "-"}</TableCell>
                      <TableCell className="font-mono text-[11px] text-zinc-500">{m.match_field ?? "-"}</TableCell>
                      <TableCell className="text-xs text-zinc-500">{m.zone ?? "-"}</TableCell>
                    </TableRow>
                  ))}
                  {!data.matches.hits.length && (
                    <TableRow><TableCell colSpan={7} className="py-8 text-center text-xs text-zinc-600">
                      No IOC matches in the selected window.
                    </TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
          </Card>
        </TabsContent>

        {/* -------- ioc store -------- */}
        <TabsContent value="iocs">
          <Card className="border-zinc-800 bg-zinc-900/60 p-3">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Filter className="h-3.5 w-3.5 text-zinc-500" />
              <Select value={iocType} onValueChange={setIocType}>
                <SelectTrigger className="h-8 w-[120px] border-zinc-800 bg-zinc-950 text-xs">
                  <SelectValue placeholder="type" />
                </SelectTrigger>
                <SelectContent className="bg-zinc-950 border-zinc-800">
                  <SelectItem value="all">all types</SelectItem>
                  {["ip", "domain", "url", "md5", "sha1", "sha256"].map((t) => (
                    <SelectItem key={t} value={t}>{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={iocStatus} onValueChange={setIocStatus}>
                <SelectTrigger className="h-8 w-[120px] border-zinc-800 bg-zinc-950 text-xs">
                  <SelectValue placeholder="status" />
                </SelectTrigger>
                <SelectContent className="bg-zinc-950 border-zinc-800">
                  <SelectItem value="active">active</SelectItem>
                  <SelectItem value="expired">expired</SelectItem>
                  <SelectItem value="all">all statuses</SelectItem>
                </SelectContent>
              </Select>
              <Input value={iocQuery} onChange={(e) => setIocQuery(e.target.value)}
                     placeholder="search value / malware family..."
                     className="h-8 w-56 border-zinc-800 bg-zinc-950 text-xs" />
              <span className="ml-auto text-[11px] text-zinc-500">{filteredIocs.length} shown</span>
            </div>
            <ScrollArea className="max-h-[400px]">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800">
                    <TableHead className="text-zinc-400">Value</TableHead>
                    <TableHead className="text-zinc-400">Type</TableHead>
                    <TableHead className="text-zinc-400">Status</TableHead>
                    <TableHead className="text-zinc-400">Confidence</TableHead>
                    <TableHead className="text-zinc-400">Family</TableHead>
                    <TableHead className="text-zinc-400">Last seen</TableHead>
                    <TableHead className="text-zinc-400">Expires</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredIocs.map((i) => (
                    <TableRow key={i.id} className="cursor-pointer border-zinc-800/70 hover:bg-zinc-800/40"
                              onClick={() => setIocDetail(i)}>
                      <TableCell className="max-w-[280px] truncate font-mono text-xs text-zinc-200">
                        {i.ioc_value}
                      </TableCell>
                      <TableCell><Badge variant="outline" className="text-[10px] border-zinc-800 text-zinc-400">{i.ioc_type}</Badge></TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`text-[10px] ${i.status === "active"
                          ? "border-emerald-900 bg-emerald-950/60 text-emerald-300"
                          : "border-zinc-800 bg-zinc-900 text-zinc-500"}`}>
                          {i.status}
                        </Badge>
                      </TableCell>
                      <TableCell><ConfidenceChip level={i.confidence} /></TableCell>
                      <TableCell className="text-xs text-zinc-300">{i.malware ?? "-"}</TableCell>
                      <TableCell className="whitespace-nowrap text-[11px] text-zinc-500">{timeAgo(i.last_seen)}</TableCell>
                      <TableCell className="whitespace-nowrap text-[11px] text-zinc-500">{i.expires_at ? timeAgo(i.expires_at) : "-"}</TableCell>
                    </TableRow>
                  ))}
                  {!filteredIocs.length && (
                    <TableRow><TableCell colSpan={7} className="py-8 text-center text-xs text-zinc-600">
                      No IOCs match the filters.
                    </TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
          </Card>
        </TabsContent>

      </Tabs>

      {/* match detail sheet */}
      <Sheet open={!!matchDetail} onOpenChange={(v) => !v && setMatchDetail(null)}>
        <SheetContent className="w-full border-zinc-800 bg-zinc-950 sm:max-w-lg">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2 text-sm text-zinc-200">
              <ShieldAlert className="h-4 w-4 text-red-400" /> IOC match detail
            </SheetTitle>
          </SheetHeader>
          {matchDetail && (
            <div className="mt-2 space-y-3">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/70 p-3">
                <div className="font-mono text-sm text-zinc-100">{matchDetail.ioc_value}</div>
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  <Badge variant="outline" className="text-[10px] border-zinc-800 text-zinc-400">{matchDetail.ioc_type}</Badge>
                  <ConfidenceChip level={matchDetail.ioc_confidence} />
                  <Badge variant="outline" className="text-[10px] border-violet-900 bg-violet-950/50 text-violet-300">
                    {matchDetail.ioc_source}
                  </Badge>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  ["seen", fmtTime(matchDetail["@timestamp"])],
                  ["matched on", matchDetail.match_field ?? "-"],
                  ["source host", matchDetail.source_ip ?? "-"],
                  ["destination", matchDetail.destination_ip ?? "-"],
                  ["zone", matchDetail.zone ?? "-"],
                  ["sensor", matchDetail.sensor_id],
                  ["event", matchDetail.event_id],
                  ["event index", matchDetail.event_index ?? "-"],
                  ["ioc first seen", matchDetail.first_seen ? fmtTime(matchDetail.first_seen) : "-"],
                  ["ioc last seen", matchDetail.last_seen ? fmtTime(matchDetail.last_seen) : "-"],
                  ["ioc expires", matchDetail.expires_at ? fmtTime(matchDetail.expires_at) : "no expiry"],
                ].map(([k, v]) => (
                  <div key={k} className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
                    <div className="text-[9.5px] uppercase tracking-wide text-zinc-600">{k}</div>
                    <div className="mt-0.5 truncate font-mono text-[11px] text-zinc-300">{v}</div>
                  </div>
                ))}
              </div>
              {onOpenEvent && (
                <Button size="sm" variant="outline"
                        className="w-full border-zinc-700 text-zinc-200 hover:bg-zinc-800"
                        onClick={() => onOpenEvent(matchDetail.event_id, matchDetail["@timestamp"])}>
                  <Search className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                  Open in Event Search (this event)
                </Button>
              )}
              {/* v0.12.1: related alerts for the same host */}
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
                    related alerts {host ? `(host ${host})` : ""}
                  </span>
                  {related && related.length > 0 && (
                    <span className="text-[10px] text-zinc-500">{related.length} recent</span>
                  )}
                </div>
                <div className="space-y-1.5">
                  {relatedLoading && (
                    <div className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2 text-[11px] text-zinc-500">
                      loading recent alerts...
                    </div>
                  )}
                  {!relatedLoading && related && related.length === 0 && (
                    <div className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2 text-[11px] text-zinc-500">
                      No recent alerts for this host - the match alone has no
                      corroborating detection yet.
                    </div>
                  )}
                  {!relatedLoading && (related ?? []).map((a) => (
                    <div key={a.alert_id}
                         className="flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-1.5">
                      <Badge variant="outline" className={`shrink-0 text-[9px] ${a.severity === "critical" || a.severity === "high"
                        ? "border-red-900 bg-red-950/50 text-red-300"
                        : a.severity === "medium"
                          ? "border-amber-900 bg-amber-950/50 text-amber-300"
                          : "border-zinc-800 text-zinc-400"}`}>
                        {a.severity}
                      </Badge>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[11px] text-zinc-300">{alertTitle(a.title)}</div>
                        <div className="text-[9.5px] text-zinc-600">
                          {a.alert_type} · {a.status} · {timeAgo(a.last_seen)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-lg border border-amber-900/50 bg-amber-950/25 px-3 py-2 text-[11px] leading-relaxed text-amber-200/90">
                This match is contextual evidence collected from threat intelligence.
                Verify the host and connection before taking response actions.
              </div>
              <div>
                <div className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-zinc-600">raw document</div>
                <JsonViewer data={matchDetail} maxHeight={220} />
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ioc detail sheet */}
      <Sheet open={!!iocDetail} onOpenChange={(v) => !v && setIocDetail(null)}>
        <SheetContent className="w-full border-zinc-800 bg-zinc-950 sm:max-w-lg">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2 text-sm text-zinc-200">
              <Fingerprint className="h-4 w-4 text-sky-400" /> IOC detail
            </SheetTitle>
          </SheetHeader>
          {iocDetail && (
            <div className="mt-2 space-y-3">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/70 p-3">
                <div className="break-all font-mono text-sm text-zinc-100">{iocDetail.ioc_value}</div>
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  <Badge variant="outline" className="text-[10px] border-zinc-800 text-zinc-400">{iocDetail.ioc_type}</Badge>
                  <ConfidenceChip level={iocDetail.confidence} />
                  <Badge variant="outline" className={`text-[10px] ${iocDetail.status === "active"
                    ? "border-emerald-900 bg-emerald-950/60 text-emerald-300" : "border-zinc-800 text-zinc-500"}`}>
                    {iocDetail.status}
                  </Badge>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  ["family", iocDetail.malware ?? "-"],
                  ["first seen", timeAgo(iocDetail.first_seen)],
                  ["last seen", timeAgo(iocDetail.last_seen)],
                  ["expires", iocDetail.expires_at ? timeAgo(iocDetail.expires_at) : "-"],
                ].map(([k, v]) => (
                  <div key={k} className="rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-2">
                    <div className="text-[9.5px] uppercase tracking-wide text-zinc-600">{k}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-zinc-300">{v}</div>
                  </div>
                ))}
              </div>
              {iocDetail.tags?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {iocDetail.tags.map((t) => (
                    <Badge key={t} variant="outline" className="text-[10px] border-zinc-800 text-zinc-400">{t}</Badge>
                  ))}
                </div>
              )}
              {/* v0.12.9: per-IOC activity on THIS network + structured
                  provenance (was a raw JSON dump that hid the story) */}
              <IocActivityPanel iocValue={iocDetail.ioc_value}
                                onOpenEvent={onOpenEvent} />
              <div>
                <div className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
                  provenance (feed sources)
                </div>
                <IocProvenance iocValue={iocDetail.ioc_value}
                               fallback={<JsonViewer data={iocDetail} maxHeight={200} />} />
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

    </div>
  );
}
