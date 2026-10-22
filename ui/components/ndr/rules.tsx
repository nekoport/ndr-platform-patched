"use client";

// Rule Manager view (Phase 6).
// Where operators live-manage the Suricata rule set:
//   - update: regenerate suricata.rules from Emerging Threats (suricata-update)
//             and attempt a live reload over the unix command socket
//   - disable/enable: per-SID switch backed by disable.conf on the shared
//             rules volume - the exact mechanism suricata-update documents,
//             so UI state, CLI (make rule-update) and the sensor agree
// Guardrail: toggles and updates are restricted to administrator /
// security_engineer and fully audited; the audit trail records who
// changed what and when.

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
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import {
  CheckCircle2, CircleSlash, Download, FlaskConical, Info, ListFilter,
  Pencil, Plus, RefreshCw, Search, ShieldCheck, Trash2,
  Wifi, WifiOff, XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createCustomRule, deleteCustomRule, getRulesStatus, getRulesSummary,
  listRules, listZeekRules, toggleRule, updateCustomRule, updateRulesNow,
  validateRuleText,
} from "@/lib/ndr/api";
import { DEMO_MODE } from "@/lib/ndr/api";
import type {
  RuleRow, RulesList, RulesStatus, RulesSummary, RuleValidateResult,
  ZeekScriptList,
} from "@/lib/ndr/types";
import { Paginator, StatCard, fmtNumber, fmtTime, timeAgo } from "./shared";

const ACTION_STYLE: Record<string, string> = {
  alert: "bg-amber-950/70 text-amber-300 border-amber-900",
  drop: "bg-red-950/70 text-red-300 border-red-900",
  pass: "bg-zinc-800 text-zinc-300 border-zinc-700",
  reject: "bg-red-950/70 text-red-300 border-red-900",
};

const PRIORITY_LABEL: Record<number, string> = {
  1: "high", 2: "medium", 3: "low", 4: "info",
};

// v0.12.7: rule source taxonomy - three DISTINCT sources, one manager:
//   suricata = subscribed Emerging Threats ruleset (editable state)
//   local    = operator-authored custom rules (editable text)
//   zeek     = policy SCRIPTS loaded from local.zeek (read-only)
const SOURCE_TABS = [
  { value: "all", label: "All rules" },
  { value: "suricata", label: "Suricata (ET)" },
  { value: "local", label: "Lokal (custom)" },
  { value: "zeek", label: "Zeek (scripts)" },
] as const;

type SourceTab = (typeof SOURCE_TABS)[number]["value"];

const SOURCE_BADGE: Record<string, string> = {
  local: "border-amber-900 bg-amber-950/60 text-amber-300",
  suricata: "border-sky-900 bg-sky-950/60 text-sky-300",
};

function SourceBadge({ source }: { source?: "local" | "suricata" | null }) {
  const s = source ?? "suricata";
  return (
    <Badge variant="outline"
           className={`text-[9px] uppercase tracking-wide ${SOURCE_BADGE[s] ?? SOURCE_BADGE.suricata}`}>
      {s === "local" ? "lokal" : "suricata (ET)"}
    </Badge>
  );
}

function HitsBar({ hits, max }: { hits: number; max: number }) {
  if (hits <= 0) return <span className="text-xs text-zinc-600">-</span>;
  const pct = Math.max(8, Math.round((hits / Math.max(max, 1)) * 100));
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-zinc-800">
        <div className="h-full rounded-full bg-amber-500/80" style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-xs tabular-nums text-zinc-400">{fmtNumber(hits)}</span>
    </div>
  );
}

// v0.12.8: module-level stale-while-revalidate cache. Re-entering the
// Rule Manager used to show a spinner on EVERY menu open (the view
// remounts on each navigation) and - when the backend had a hiccup - an
// error instead of data. Now the last fetched page for the EXACT filter
// key renders instantly and is silently refreshed in the background; a
// failed refresh keeps the stale data on screen.
const rulesListCache = new Map<string, RulesList>();
let rulesSummaryCache: RulesSummary | null = null;
let rulesZeekCache: ZeekScriptList | null = null;

export function RulesView({ canEdit, username }: {
  canEdit: boolean;
  username: string;
}) {
  const { toast } = useToast();
  const [summary, setSummary] = useState<RulesSummary | null>(null);
  // v0.16.1 (P1-3): status ringan (file/socket) TIDAK tergantung parsing
  // 45 MB - kartu KPI tetap benar meski summary gagal/lambat.
  const [ruleStatus, setRuleStatus] = useState<RulesStatus | null>(null);
  const [list, setList] = useState<RulesList | null>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [updateLog, setUpdateLog] = useState<string | null>(null);
  const [pendingNote, setPendingNote] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [category, setCategory] = useState<string>("all");
  const [status, setStatus] = useState<"all" | "enabled" | "disabled">("all");
  const [busySid, setBusySid] = useState<number | null>(null);
  // v0.12.7: source tab + REAL server-side pagination (limit/offset walk
  // the full rule set - 53k ET rules no longer truncate at the first 200)
  const [sourceTab, setSourceTab] = useState<SourceTab>("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [zeek, setZeek] = useState<ZeekScriptList | null>(null);

  // ------------------------------ custom rule editor (v0.11)
  const [editorOpen, setEditorOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<RuleRow | null>(null);
  const [draftText, setDraftText] = useState("");
  const [vRes, setVRes] = useState<RuleValidateResult | null>(null);
  const [editorBusy, setEditorBusy] = useState(false);

  useEffect(() => {
    if (!editorOpen) return;
    let alive = true;
    const t = setTimeout(async () => {
      try {
        const res = await validateRuleText(draftText);
        if (alive) setVRes(res);
      } catch (e) {
        if (alive) setVRes({ ok: false, error: String(e) });
      }
    }, 250);
    return () => { alive = false; clearTimeout(t); };
  }, [draftText, editorOpen]);

  function openEditor(rule?: RuleRow) {
    setEditTarget(rule ?? null);
    setDraftText(rule?.rule_text ??
      'alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"NDRLAB ..."; '
      + 'flow:established,to_server; http.user_agent; content:"..."; '
      + 'classtype:attempted-recon; sid:1000001; rev:1;)');
    setVRes(null);
    setEditorOpen(true);
  }

  async function saveCustom() {
    if (!vRes?.ok || editorBusy) return;
    setEditorBusy(true);
    try {
      if (editTarget) {
        await updateCustomRule(editTarget.sid, { rule_text: draftText.trim() });
        toast({ title: `SID ${editTarget.sid} updated`,
                description: "rule re-synced to the engine" });
      } else {
        const created = await createCustomRule({ rule_text: draftText.trim() });
        toast({ title: `Custom rule SID ${created.sid} created`,
                description: "written to custom.rules and synced into suricata.rules" });
      }
      setEditorOpen(false);
      void refresh();
    } catch (e) {
      toast({ title: "Save failed", description: String(e), variant: "destructive" });
    } finally {
      setEditorBusy(false);
    }
  }

  async function handleDeleteCustom(rule: RuleRow) {
    if (!confirm(`Delete custom rule SID ${rule.sid} ("${rule.msg}")? This removes it from the engine.`)) return;
    try {
      await deleteCustomRule(rule.sid);
      toast({ title: `SID ${rule.sid} deleted` });
      void refresh();
    } catch (e) {
      toast({ title: "Delete failed", description: String(e), variant: "destructive" });
    }
  }

  // v0.12.8: debounce the search box - every keystroke used to fire a
  // server round-trip (and a backend page rebuild while the user typed)
  const [qInput, setQInput] = useState("");
  useEffect(() => {
    const t = setTimeout(() => {
      setQ((prev) => (prev === qInput ? prev : qInput));
      setPage(1);
    }, 250);
    return () => clearTimeout(t);
  }, [qInput]);

  const refresh = useCallback(async () => {
    const params = {
      q: q || undefined,
      category: category === "all" ? undefined : category,
      status,
      // "zeek" never reaches the list endpoint (that tab loads the
      // read-only script inventory instead)
      source: sourceTab === "all" || sourceTab === "zeek"
        ? undefined : sourceTab,
      limit: pageSize,
      offset: (page - 1) * pageSize,
    };
    const cacheKey = JSON.stringify(params);
    // stale-while-revalidate: paint the cached page instantly, no spinner
    const cachedList = rulesListCache.get(cacheKey);
    if (cachedList && rulesSummaryCache) {
      setList(cachedList);
      setSummary(rulesSummaryCache);
      setLoading(false);
    } else if (sourceTab === "zeek" && rulesZeekCache && rulesSummaryCache) {
      setZeek(rulesZeekCache);
      setSummary(rulesSummaryCache);
      setLoading(false);
    } else {
      setLoading(true);
    }
    try {
      if (sourceTab === "zeek") {
        // Zeek tab: read-only policy inventory (no toggle/edit by design)
        const [s, z] = await Promise.all([getRulesSummary(), listZeekRules()]);
        setSummary(s);
        rulesSummaryCache = s;
        rulesZeekCache = z;
        setZeek(z);
        setList(null);
      } else {
        const [s, l] = await Promise.all([getRulesSummary(), listRules(params)]);
        setSummary(s);
        rulesSummaryCache = s;
        rulesListCache.set(cacheKey, l);
        setList(l);
        setZeek(null);
        // result set shrank under us - snap back to the last valid page
        if (l.total > 0 && (page - 1) * pageSize >= l.total) {
          const last = Math.max(1, Math.ceil(l.total / pageSize));
          setPage(last);
          const again = await listRules({ ...params, offset: (last - 1) * pageSize });
          rulesListCache.set(JSON.stringify({ ...params, offset: (last - 1) * pageSize }), again);
          setList(again);
        }
      }
    } catch (e) {
      // v0.12.8: with a cached page on screen a refresh failure is only
      // a soft warning - the operator keeps working with the stale data
      if (cachedList || (sourceTab === "zeek" && rulesZeekCache)) {
        toast({ title: "Refresh failed - showing last known rules",
                description: String(e), variant: "destructive" });
      } else {
        toast({ title: "Failed to load rules", description: String(e), variant: "destructive" });
      }
    } finally {
      setLoading(false);
    }
  }, [q, category, status, sourceTab, page, pageSize, toast]);

  useEffect(() => { void refresh(); }, [refresh]);

  // v0.16.1 (P1-3): status endpoint di-fetch TERPISAH dari summary/list.
  // Dulu satu Promise.all membuat kegagalan mana pun mengosongkan
  // seluruh Rule Manager ("not found"/"offline" padahal backend hidup).
  useEffect(() => {
    let alive = true;
    getRulesStatus().then((s) => { if (alive) setRuleStatus(s); });
    return () => { alive = false; };
  }, []);

  const maxHits = useMemo(() =>
    Math.max(1, ...(list?.items ?? []).map((r) => r.hits_7d ?? 0)), [list]);

  async function handleToggle(rule: RuleRow) {
    if (!canEdit || busySid !== null) return;
    const next = !rule.enabled;
    setBusySid(rule.sid);
    // optimistic flip; revert on failure
    if (list) {
      setList({
        ...list,
        items: list.items.map((r) => r.sid === rule.sid ? { ...r, enabled: next } : r),
      });
    }
    try {
      const res = await toggleRule(rule.sid, next, username);
      if (!res.update_ok) {
        toast({
          title: `SID ${res.sid} staged but not regenerated`,
          description: res.error ?? "suricata-update failed - change applies on next successful update",
          variant: "destructive",
        });
      } else if (!res.reloaded) {
        setPendingNote(`SID ${res.sid} ${next ? "enabled" : "disabled"} - reload pending: ${res.reload_detail}`);
      } else {
        setPendingNote(null);
        toast({ title: `SID ${res.sid} ${next ? "enabled" : "disabled"}`,
                description: "rules regenerated and reloaded live" });
      }
    } catch (e) {
      // revert optimistic flip
      if (list) {
        setList({
          ...list,
          items: list.items.map((r) => r.sid === rule.sid ? { ...r, enabled: rule.enabled } : r),
        });
      }
      toast({ title: "Toggle failed", description: String(e), variant: "destructive" });
    } finally {
      setBusySid(null);
      void refresh();
    }
  }

  async function handleUpdate() {
    if (updating) return;
    setUpdating(true);
    setUpdateLog(null);
    try {
      const res = await updateRulesNow();
      setUpdateLog(res.output || (res.ok ? "update finished" : res.error || "update failed"));
      if (res.ok) {
        toast({
          title: "Rule update finished",
          description: `${res.rules_loaded ?? "?"} rules loaded${res.reloaded ? " and reloaded live" : ""}`,
        });
        if (!res.reloaded) {
          setPendingNote(`update applied - reload pending: ${res.reload_detail}`);
        }
      } else {
        toast({ title: "Rule update failed", description: res.error ?? "unknown error", variant: "destructive" });
      }
    } catch (e) {
      toast({ title: "Rule update failed", description: String(e), variant: "destructive" });
    } finally {
      setUpdating(false);
      void refresh();
    }
  }

  const categories = useMemo(() => {
    const set = new Set<string>((list?.items ?? []).map((r) => r.classtype ?? "unclassified"));
    if (summary) Object.keys(summary.top_categories).forEach((c) => set.add(c));
    return Array.from(set).sort();
  }, [list, summary]);

  return (
    <div className="space-y-4">
      {/* intro guardrail */}
      <Card className="border-zinc-800 bg-zinc-900/50 p-3">
        <div className="flex items-start gap-2 text-xs text-zinc-400">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
          <p>
            This is the central place to manage the Suricata rule set: <span className="text-zinc-200">update</span> the
            Emerging Threats rules, and <span className="text-zinc-200">enable / disable</span> individual rules by SID.
            Disabling writes the SID to <code className="rounded bg-zinc-800 px-1">disable.conf</code> on the shared rules
            volume and regenerates <code className="rounded bg-zinc-800 px-1">suricata.rules</code> - the same mechanism as
            <code className="rounded bg-zinc-800 px-1"> make rule-update</code>, so CLI and UI can never diverge.
            Every change is written to the audit log with actor and timestamp.
          </p>
        </div>
      </Card>

      {/* summary cards - v0.16.1 (P1-3): file/sensor dibaca dari /status
          (ringan, path persis yang dilihat API); bila belum terbaca,
          label jujur "memuat/unknown" - BUKAN klaim "not found"/"offline"
          yang menyesatkan. */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard title="Rules loaded" value={summary ? fmtNumber(summary.total) : "..."}
                  sub={
                    summary?.rules_file_exists
                      ? `file updated ${timeAgo(summary.rules_file_updated)}`
                      : ruleStatus
                        ? (ruleStatus.rules_file_exists
                            ? `file updated ${timeAgo(ruleStatus.rules_file_updated)}`
                            : `file tidak ada di API (${ruleStatus.rules_file})`)
                        : "memuat status file..."
                  } />
        <StatCard title="Enabled" value={summary ? fmtNumber(summary.enabled) : "..."}
                  sub={summary ? `${Object.entries(summary.actions).map(([k, v]) => `${k}: ${v}`).join(" / ") || "-"}` : undefined}
                  tone="ok" />
        <StatCard title="Disabled" value={summary ? fmtNumber(summary.disabled) : "..."}
                  sub="SIDs in disable.conf"
                  tone={summary && summary.disabled > 0 ? "alert" : "default"} />
        <StatCard
          title="Sensor"
          value={ruleStatus
            ? (ruleStatus.sensor_online ? "online" : "offline")
            : summary
              ? (summary.sensor_online ? "online" : "offline")
              : "..."}
          sub={ruleStatus
            ? (ruleStatus.socket_present
                ? `socket ${ruleStatus.unix_socket} - live reload siap`
                : `socket tidak ada di API (${ruleStatus.unix_socket})`)
            : "memuat status sensor..."}
          tone={(ruleStatus?.sensor_online ?? summary?.sensor_online) ? "ok" : (ruleStatus || summary ? "alert" : "default")} />
      </div>

      {/* pending reload banner */}
      {pendingNote && (
        <Card className="border-amber-900 bg-amber-950/40 p-3 text-xs text-amber-200">
          <div className="flex items-start gap-2">
            <FlaskConical className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{pendingNote}</span>
          </div>
        </Card>
      )}

      {/* v0.12.7: rule-source tabs - bedakan rule lokal / suricata / zeek */}
      <div className="flex flex-wrap items-center gap-1.5">
        {SOURCE_TABS.map((t) => {
          const active = sourceTab === t.value;
          const count = t.value === "all" ? summary?.total
            : t.value === "zeek" ? zeek?.load_count
            : summary?.by_source?.[t.value];
          return (
            <button key={t.value}
                    onClick={() => { setSourceTab(t.value); setPage(1); }}
                    className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors ${
                      active
                        ? "ndr-gloss border-sky-600/60 font-medium text-sky-100"
                        : "border-zinc-800 bg-zinc-900/60 text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
                    }`}>
              {t.label}
              {count != null && (
                <span className={`rounded-full px-1.5 py-0.5 text-[9px] font-semibold ${active ? "bg-sky-950/80 text-sky-200" : "bg-zinc-800 text-zinc-400"}`}>
                  {fmtNumber(count)}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        {sourceTab !== "zeek" && (
          <>
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-500" />
              <Input value={qInput} onChange={(e) => setQInput(e.target.value)}
                     placeholder="Search msg, SID, classtype..."
                     className="w-64 border-zinc-800 bg-zinc-900 pl-8 text-sm" />
            </div>
            <Select value={category} onValueChange={(v) => { setCategory(v); setPage(1); }}>
              <SelectTrigger className="w-52 border-zinc-800 bg-zinc-900 text-sm">
                <ListFilter className="mr-1 h-3.5 w-3.5 text-zinc-500" />
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent className="max-h-72">
                <SelectItem value="all">All categories</SelectItem>
                {categories.map((c) => (
                  <SelectItem key={c} value={c}>{c}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={status} onValueChange={(v) => { setStatus(v as typeof status); setPage(1); }}>
              <SelectTrigger className="w-40 border-zinc-800 bg-zinc-900 text-sm">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All states</SelectItem>
                <SelectItem value="enabled">Enabled only</SelectItem>
                <SelectItem value="disabled">Disabled only</SelectItem>
              </SelectContent>
            </Select>
          </>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void refresh()}
                  className="border-zinc-800 text-zinc-300 hover:bg-zinc-800">
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          {canEdit && (
            <Button size="sm" variant="outline"
                    onClick={() => openEditor()}
                    className="border-emerald-800 text-emerald-300 hover:bg-emerald-950">
              <Plus className="mr-1.5 h-3.5 w-3.5" />
              New rule
            </Button>
          )}
          {canEdit ? (
            <Button size="sm" onClick={() => void handleUpdate()}
                    disabled={updating}
                    className="bg-emerald-800 text-emerald-100 hover:bg-emerald-700">
              <Download className={`mr-1.5 h-3.5 w-3.5 ${updating ? "animate-bounce" : ""}`} />
              {updating ? "Updating rules..." : "Update rules"}
            </Button>
          ) : (
            <Badge variant="outline" className="border-zinc-800 text-[10px] text-zinc-500">
              view-only role
            </Badge>
          )}
        </div>
      </div>

      {/* update log */}
      {updateLog && (
        <Card className="border-zinc-800 bg-black/60 p-3">
          <div className="mb-1 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-widest text-zinc-500">
            <ShieldCheck className="h-3 w-3 text-emerald-500" />
            suricata-update output
          </div>
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-emerald-300/90">
            {updateLog}
          </pre>
        </Card>
      )}

      {/* rules table (Suricata + lokal) | zeek policy inventory */}
      {sourceTab === "zeek" ? (
        <Card className="bg-zinc-900/60 border-zinc-800">
          <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 px-4 py-3 text-xs text-zinc-400">
            <ShieldCheck className="h-3.5 w-3.5 text-sky-400" />
            <span className="font-medium text-zinc-200">Zeek policy inventory</span>
            <span>- read-only: Zeek detection lives in SCRIPTS loaded from local.zeek, not in toggleable rules</span>
          </div>
          {zeek?.exists ? (
            <>
              <div className="flex flex-wrap gap-2 px-4 py-2.5 text-[11px] text-zinc-500">
                <Badge variant="outline" className="border-zinc-700 text-zinc-400">{fmtNumber(zeek.total_lines ?? 0)} lines</Badge>
                <Badge variant="outline" className="border-sky-900 bg-sky-950/60 text-sky-300">{fmtNumber(zeek.load_count ?? 0)} @load scripts</Badge>
                <Badge variant="outline" className="border-zinc-800 text-zinc-500">{fmtNumber(zeek.comment_lines ?? 0)} comment lines</Badge>
                <span className="ml-auto font-mono text-[10px] text-zinc-600">{zeek.path}</span>
              </div>
              <ScrollArea className="whitespace-nowrap">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800/80">
                      <TableHead className="w-16">Line</TableHead>
                      <TableHead className="w-28">Kind</TableHead>
                      <TableHead className="min-w-[420px]">Directive</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {zeek.items.map((it) => (
                      <TableRow key={it.line} className="border-zinc-800/60">
                        <TableCell className="font-mono text-xs tabular-nums text-zinc-500">{it.line}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="font-mono text-[10px] uppercase">{it.kind}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-zinc-300">{it.text}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>
              {zeek.note && (
                <p className="border-t border-zinc-800 px-4 py-2.5 text-[11px] text-zinc-600">{zeek.note}</p>
              )}
            </>
          ) : (
            <p className="px-4 py-10 text-center text-xs text-zinc-500">
              {zeek?.note ?? "Zeek inventory unavailable - the local.zeek mount is not readable from the API container."}
            </p>
          )}
        </Card>
      ) : (
      <Card className="bg-zinc-900/60 border-zinc-800">
        <ScrollArea className="whitespace-nowrap">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800/80">
                <TableHead className="w-16">On</TableHead>
                <TableHead className="w-20">Action</TableHead>
                <TableHead className="w-20">SID</TableHead>
                <TableHead className="w-28"
                           title="v0.12.7: rule source - lokal (operator-authored) vs Suricata (subscribed Emerging Threats set)">Source</TableHead>
                <TableHead className="min-w-[320px]">Message</TableHead>
                <TableHead className="w-44">Category</TableHead>
                <TableHead className="w-16">Prio</TableHead>
                <TableHead className="w-24"
                           title="v0.16.0 (req 15): hit 24 jam dari tabel rule_stats (refresh 15 menit)">Hits 24h</TableHead>
                <TableHead className="w-32"
                           title="v0.16.0 (req 15): hit 7 hari; >1000 = badge noisy">Hits 7d</TableHead>
                <TableHead className="w-32"
                           title="v0.16.0 (req 15): hit terakhir + severity maksimum">Last hit</TableHead>
                <TableHead className="w-40">Changed by</TableHead>
                {canEdit && <TableHead className="w-16">Edit</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && (list?.items.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={canEdit ? 10 : 9} className="py-8 text-center text-sm text-zinc-500">
                    Loading rules...
                  </TableCell>
                </TableRow>
              )}
              {!loading && (list?.items.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={canEdit ? 10 : 9} className="py-8 text-center text-sm text-zinc-500">
                    No rules match the current filters.
                    {summary && !summary.rules_file_exists && " suricata.rules was not found - run 'Update rules' or 'make rule-update' to generate it."}
                  </TableCell>
                </TableRow>
              )}
              {(list?.items ?? []).map((rule) => (
                <TableRow key={rule.sid} className={`border-zinc-800/60 ${rule.enabled ? "" : "opacity-60"}`}>
                  <TableCell>
                    <Switch checked={rule.enabled} disabled={!canEdit || busySid === rule.sid}
                            onCheckedChange={() => void handleToggle(rule)}
                            aria-label={`Toggle rule ${rule.sid}`} />
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline"
                           className={`font-mono text-[10px] uppercase ${ACTION_STYLE[rule.action] ?? ACTION_STYLE.pass}`}>
                      {rule.action}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs tabular-nums text-zinc-400">{rule.sid}</TableCell>
                  <TableCell><SourceBadge source={rule.source} /></TableCell>
                  <TableCell className="max-w-[420px] truncate text-xs text-zinc-200" title={rule.msg ?? undefined}>
                    {rule.msg ?? <span className="text-zinc-600">(metadata not cached)</span>}
                  </TableCell>
                  <TableCell>
                    <span className="rounded bg-zinc-800/80 px-1.5 py-0.5 text-[10px] text-zinc-400">
                      {rule.classtype ?? "unclassified"}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-zinc-400">
                    {rule.priority != null ? `${rule.priority} ${PRIORITY_LABEL[rule.priority] ?? ""}` : "-"}
                  </TableCell>
                  {/* v0.16.0 (req 14/15): kolom statistik dari rule_stats */}
                  <TableCell className="text-xs tabular-nums text-zinc-300">
                    {rule.hits_24h != null ? fmtNumber(rule.hits_24h) : "-"}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      <HitsBar hits={rule.hits_7d ?? 0} max={maxHits} />
                      {rule.noisy && (
                        <Badge className="bg-amber-500/15 text-amber-400
                                          border-amber-500/30 text-[9px] px-1"
                               title="hits 7 hari > 1000 - pertimbangkan whitelist/turning">
                          noisy
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-[11px] text-zinc-500">
                    <div>{rule.last_hit_at ? timeAgo(rule.last_hit_at) : "-"}</div>
                    {rule.sev_max && (
                      <span className={`text-[10px] uppercase ${
                        rule.sev_max === "critical" || rule.sev_max === "high"
                          ? "text-rose-400" : "text-zinc-600"}`}>
                        max {rule.sev_max}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-[11px] text-zinc-500">
                    {rule.changed_by ? (
                      <span className="flex items-center gap-1">
                        <CircleSlash className="h-3 w-3" />
                        {rule.changed_by}, {timeAgo(rule.changed_at)}
                      </span>
                    ) : "-"}
                  </TableCell>
                  {canEdit && (
                    <TableCell className="w-16">
                      {rule.custom ? (
                        <span className="flex items-center gap-1">
                          <Button size="icon" variant="ghost"
                                  className="h-6 w-6 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                                  title="Edit rule text"
                                  onClick={() => openEditor(rule)}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button size="icon" variant="ghost"
                                  className="h-6 w-6 text-zinc-500 hover:bg-red-950/60 hover:text-red-300"
                                  title="Delete custom rule"
                                  onClick={() => void handleDeleteCustom(rule)}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </span>
                      ) : null}
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
        {list && (
          <div className="border-t border-zinc-800/80">
            {/* v0.12.7: server-side pagination - walks the FULL rule set
                (suricata.rules can carry 50k+ rules; the old fixed
                limit-200 fetch silently hid everything past row 200) */}
            <Paginator page={page} pageSize={pageSize} total={list.total}
                       onPage={setPage}
                       onPageSize={(s) => { setPageSize(s); setPage(1); }} />
          </div>
        )}
      </Card>
      )}

      {/* footer facts */}
      <div className="flex flex-wrap items-center gap-4 text-[11px] text-zinc-600">
        <span className="flex items-center gap-1.5">
          {summary?.sensor_online
            ? <Wifi className="h-3.5 w-3.5 text-emerald-500" />
            : <WifiOff className="h-3.5 w-3.5 text-amber-500" />}
          {summary?.sensor_online
            ? "sensor unix socket detected - toggles reload the engine live"
            : "sensor offline - toggles are staged in disable.conf and apply at next sensor start"}
        </span>
        {summary && summary.skipped_lines > 0 && (
          <span>{summary.skipped_lines} unparseable line(s) in suricata.rules (ignored by the engine)</span>
        )}
        {list && list.items.length < list.total && (
          <span>showing {list.items.length} of {list.total} matching rules (page {page})</span>
        )}
        {list && (
          <span title="v0.16.0: statistik hit dari tabel rule_stats di Postgres, di-refresh otomatis (RULE_STATS_REFRESH_MIN)">
            rule stats: {list.stats_available ? "aktif (rule_stats)" : "menunggu refresh pertama - hit 7d on-the-fly"}
          </span>
        )}
        {sourceTab === "zeek" && zeek && (
          <span>zeek policy: {zeek.items.length} directive line(s) inventoried (read-only)</span>
        )}
        {DEMO_MODE && <span className="flex items-center gap-1"><FlaskConical className="h-3 w-3" /> demo dataset - not the live rules volume</span>}
        <span className="ml-auto">last regenerated: {fmtTime(summary?.rules_file_updated)}</span>
      </div>

      {/* custom rule editor dialog (v0.11) */}
      <Dialog open={editorOpen}
              onOpenChange={(open) => { if (!open) { setEditorOpen(false); setEditTarget(null); } }}>
        <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">
              {editTarget ? `Edit custom rule SID ${editTarget.sid}` : "New custom Suricata rule"}
            </DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-1">
            <div className="space-y-1.5">
              <Label htmlFor="rule-text">Rule text (single line)</Label>
              <Textarea id="rule-text" value={draftText} spellCheck={false}
                        onChange={(e) => setDraftText(e.target.value)}
                        className="min-h-24 border-zinc-800 bg-black/60 font-mono text-[12px] leading-relaxed text-emerald-200" />
            </div>
            <div className="rounded-md border border-zinc-800 bg-zinc-900/60 p-2.5 text-xs">
              {vRes === null && (
                <span className="text-zinc-500">validating...</span>
              )}
              {vRes?.ok && vRes.parsed && (
                <div className="space-y-1">
                  <p className="flex items-center gap-1.5 text-emerald-300">
                    <CheckCircle2 className="h-3.5 w-3.5" /> valid rule
                  </p>
                  <div className="flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[11px] text-zinc-400">
                    <span>sid: <span className="text-zinc-200">{vRes.parsed.sid}</span></span>
                    <span>action: <span className="text-zinc-200">{vRes.parsed.action}</span></span>
                    <span>proto: <span className="text-zinc-200">{vRes.parsed.protocol}</span></span>
                    <span>rev: <span className="text-zinc-200">{vRes.parsed.rev ?? "-"}</span></span>
                    <span>classtype: <span className="text-zinc-200">{vRes.parsed.classtype ?? "-"}</span></span>
                    <span>prio: <span className="text-zinc-200">{vRes.parsed.priority ?? "-"}</span></span>
                  </div>
                  <p className="text-[11px] text-zinc-500">msg: {vRes.parsed.msg}</p>
                </div>
              )}
              {vRes && !vRes.ok && (
                <p className="flex items-start gap-1.5 text-red-300">
                  <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {vRes.error}
                </p>
              )}
            </div>
            <p className="text-[11px] leading-relaxed text-zinc-500">
              Custom SIDs use the reserved local range <code className="rounded bg-zinc-800 px-1">1.000.000-1.999.999</code>
              {" "}so they never collide with subscribed ET rules. On save the rule is written to
              <code className="mx-1 rounded bg-zinc-800 px-1">custom.rules</code> and synced into the managed section of
              <code className="mx-1 rounded bg-zinc-800 px-1">suricata.rules</code>; the engine reloads it live when the
              unix socket is available. Every change is audited.
            </p>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => { setEditorOpen(false); setEditTarget(null); }}
                    className="text-zinc-400">Cancel</Button>
            <Button onClick={() => void saveCustom()} disabled={!vRes?.ok || editorBusy}
                    className="bg-emerald-600 text-white hover:bg-emerald-500">
              {editorBusy ? "Saving..." : editTarget ? "Save changes" : "Create rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
