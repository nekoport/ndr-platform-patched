"use client";

// PCAP & Evidence workflow panel (doc section 15 - Phase 6).
//
// Implements the analyst flow from the design doc:
//   resolve sessions for an alert/incident -> show them with an honest
//   evidence status -> analyst picks a subset -> export with manifest +
//   SHA-256 under size/duration limits -> TTL'd bundle with custody log.
// Export granularity is FILE-LEVEL for the PoC and says so everywhere.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { createPcapExport, getAlertSessions, getIncidentSessions,
         listPcapExports, pcapExportDownloadUrl } from "@/lib/ndr/api";
import { DEMO_MODE } from "@/lib/ndr/api";
import type { EvidenceSessions, PcapExportsList, PcapStatus,
              SessionRow } from "@/lib/ndr/types";
import { Archive, Database, Download, ExternalLink, Loader2,
         RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { fmtNumber, fmtTime, timeAgo } from "./shared";
import { cn } from "@/lib/utils";

/** v0.12.6: alert evidence refs (doc 8.1) rendered inside this panel. */
export interface EvidenceRef {
  event_id: string;
  index: string;
  "@timestamp": string;
}

const STATUS_META: Record<PcapStatus, { label: string; cls: string }> = {
  available: { label: "Available",
               cls: "border-emerald-800 bg-emerald-950/50 text-emerald-300" },
  partially_available: { label: "Partially available",
                         cls: "border-amber-800 bg-amber-950/40 text-amber-300" },
  expired: { label: "Expired (retention)",
             cls: "border-red-900/70 bg-red-950/30 text-red-300/90" },
  not_captured: { label: "Not captured",
                  cls: "border-zinc-800 bg-zinc-950/40 text-zinc-500" },
};

function fmtBytes(n?: number | null): string {
  if (n == null) return "-";
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function shortSha(sha?: string | null): string {
  return sha ? `${sha.slice(0, 12)}…` : "-";
}

export function EvidencePanel({ scope, scopeId, canExport, evidence }: {
  scope: "alert" | "incident";
  scopeId: string;
  canExport: boolean;
  /** v0.12.6: the alert's own trigger-event refs (doc 8.1). Merged into
   * this panel so the analyst sees ONE evidence section instead of a
   * duplicated list stacked on top of the session table. Rendered even
   * when the session lookup fails, so the section keeps its value. */
  evidence?: EvidenceRef[];
}) {
  const { toast } = useToast();
  const [data, setData] = useState<EvidenceSessions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [reason, setReason] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exports, setExports] = useState<PcapExportsList | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = scope === "alert"
        ? await getAlertSessions(scopeId)
        : await getIncidentSessions(scopeId);
      setData(res);
      setSelected(new Set(
        res.sessions.filter((s) => s.pcap_status === "available")
          .map((s) => s.doc_id)));
      setExports(await listPcapExports());
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [scope, scopeId]);

  function toggle(docId: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(docId)) next.delete(docId); else next.add(docId);
      return next;
    });
  }

  async function doExport() {
    if (!selected.size || reason.trim().length < 3) return;
    setExporting(true);
    try {
      const ref = scope === "alert" ? { alert_id: scopeId }
                                    : { incident_id: scopeId };
      const rec = await createPcapExport({
        ...ref, reason: reason.trim(), sessions: [...selected] });
      if (rec.status === "failed") {
        toast({ title: "Export recorded as failed",
                description: rec.error ?? "no evidence available",
                variant: "destructive" });
      } else {
        toast({ title: "PCAP export ready",
                description: `bundle ${shortSha(rec.bundle_sha256)} · `
                  + `${fmtBytes(rec.total_bytes)} · expires in `
                  + `${exports?.ttl_minutes ?? 60} min` });
      }
      setReason("");
      setExports(await listPcapExports());
    } catch (e) {
      toast({ title: "Export failed", description: String(e),
              variant: "destructive" });
    } finally {
      setExporting(false);
    }
  }

  // v0.12.6: trigger-evidence block stays visible across loading/error
  // states so a failing session lookup never hides the alert's own refs.
  const evidenceBlock = evidence?.length ? (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2.5">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
        Trigger evidence ({evidence.length} sample event{evidence.length === 1 ? "" : "s"})
      </div>
      <p className="mt-0.5 text-[10px] leading-relaxed text-zinc-600">
        The events that fired this alert - refs into the raw event store
        (index + event id). Session-level context follows below.
      </p>
      <div className="mt-1.5 space-y-1">
        {evidence.map((ev, i) => (
          <div key={i} className="flex items-center justify-between rounded bg-zinc-950/70 px-2 py-1.5 text-xs">
            <span className="font-mono text-zinc-400">{ev.event_id}</span>
            <span className="text-zinc-600">{ev.index}</span>
            <span className="text-zinc-500">{fmtTime(ev["@timestamp"])}</span>
          </div>
        ))}
      </div>
    </div>
  ) : null;

  if (loading) {
    return <div className="space-y-2">
      {evidenceBlock}
      <Skeleton className="h-16 bg-zinc-900" />
      <Skeleton className="h-40 bg-zinc-900" />
    </div>;
  }
  if (error || !data) {
    return <div className="space-y-2">
      {evidenceBlock}
      <p className="text-xs text-red-400">
        Failed to load sessions: {error}
      </p>
    </div>;
  }

  const cov = data.pcap;
  const avail = data.sessions.filter((s) => s.pcap_status === "available").length;
  const limits = exports?.limits;

  return (
    <div className="space-y-3">
      {evidenceBlock}

      {/* capture coverage banner (doc 15.2 - distinguishable statuses) */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2.5">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <Database className="h-3.5 w-3.5 text-violet-400" />
          <span className="font-medium text-zinc-200">Capture window</span>
          <span className="font-mono text-zinc-400">
            {cov.coverage_from ? cov.coverage_from.slice(0, 16).replace("T", " ") : "?"}
            {" → "}
            {cov.coverage_to ? cov.coverage_to.slice(0, 16).replace("T", " ") : "?"}
          </span>
          <Badge variant="outline" className="border-zinc-700 text-[10px] text-zinc-400">
            {cov.file_count ?? 0} files · {fmtBytes(cov.total_bytes)}
          </Badge>
          <Badge variant="outline"
                 className="border-violet-900 bg-violet-950/30 text-[10px] text-violet-300">
            granularity: {cov.granularity ?? "file-level"}
          </Badge>
          {data.arkime && (
            <Badge variant="outline"
                   title={data.arkime.error ?? undefined}
                   className={cn("text-[10px]",
                     data.arkime.reachable
                       ? "border-emerald-800 bg-emerald-950/40 text-emerald-300"
                       : "border-zinc-800 bg-zinc-950/40 text-zinc-500")}>
              Arkime: {data.arkime.reachable
                ? `reachable (${data.arkime.latency_ms ?? "?"} ms)`
                : "unreachable"}
            </Badge>
          )}
          <Button size="sm" variant="outline"
                  className="ml-auto border-sky-800 bg-sky-950/40 text-[11px] text-sky-300 hover:bg-sky-900/40"
                  title={data.arkime?.url
                    ? "Open the Arkime session list for this scope\'s entities and window"
                    : "Arkime viewer home"}
                  onClick={() => window.open(
                    data.arkime?.url || data.arkime_viewer_url, "_blank")}>
            <ExternalLink className="mr-1 h-3 w-3" />
            {data.arkime?.url ? "Open in Arkime (this scope)" : "Open Arkime viewer"}
          </Button>
        </div>
        {data.arkime?.expression && (
          <p className="mt-1.5 truncate font-mono text-[10px] text-zinc-600"
             title={data.arkime.expression}>
            arkime expression: {data.arkime.expression}
          </p>
        )}
        <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-500">
          {cov.note} Session window includes a {data.capture_buffer_minutes ?? 5} min
          pre/post capture buffer.
        </p>
      </div>

      {/* sessions table (doc 15.1 steps 1-3) */}
      <div className="rounded-lg border border-zinc-800">
        <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-950/70 px-3 py-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
            Sessions ({data.total}) · {avail} with PCAP available
          </span>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="ghost"
                    className="h-6 px-2 text-[10px] text-zinc-400 hover:bg-zinc-800"
                    onClick={() => setSelected(new Set(
                      data.sessions.filter((s) => s.pcap_status === "available")
                        .map((s) => s.doc_id)))}>
              select available
            </Button>
            <Button size="sm" variant="ghost"
                    className="h-6 px-2 text-[10px] text-zinc-500 hover:bg-zinc-800"
                    onClick={() => setSelected(new Set())}>
              clear
            </Button>
          </div>
        </div>
        {data.sessions.length ? (
          // v0.12.6: bounded horizontal scroll - the flow/host columns
          // forced the table wider than the sheet and clipped the
          // evidence-status column at the right edge.
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-xs">
            <thead className="bg-zinc-950/50 text-[10px] uppercase tracking-wider text-zinc-600">
              <tr>
                <th className="w-8 px-3 py-1.5"></th>
                <th className="px-3 py-1.5">Time</th>
                <th className="px-3 py-1.5">Engine</th>
                <th className="px-3 py-1.5">Flow</th>
                <th className="px-3 py-1.5 text-right">Bytes</th>
                <th className="px-3 py-1.5">Evidence status</th>
                <th className="w-10 px-3 py-1.5" title="Arkime session deep link"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/70">
              {data.sessions.map((s) => (
                <SessionRowView key={s.doc_id} row={s}
                                checked={selected.has(s.doc_id)}
                                onToggle={() => toggle(s.doc_id)} />
              ))}
            </tbody>
            </table>
          </div>
        ) : (
          <p className="px-3 py-6 text-center text-xs text-zinc-500">
            No events found for the alert entities in the selected window.
          </p>
        )}
      </div>

      {/* export form (doc 15.1 steps 4-8) */}
      {canExport && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-3">
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input value={reason}
                   onChange={(e) => setReason(e.target.value)}
                   placeholder="Reason (required - recorded in the export manifest & audit)"
                   className="flex-1 border-zinc-800 bg-zinc-950 text-xs text-zinc-200 placeholder:text-zinc-600" />
            <Button size="sm" disabled={exporting || !selected.size
                                        || reason.trim().length < 3}
                    onClick={doExport}
                    className="bg-violet-700 text-white hover:bg-violet-600">
              {exporting
                ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                : <Archive className="mr-1.5 h-3.5 w-3.5" />}
              Export {selected.size} session{selected.size === 1 ? "" : "s"}
            </Button>
          </div>
          <p className="mt-1.5 text-[10px] text-zinc-600">
            Policy: max {limits?.max_files ?? 5} files ·{" "}
            {fmtBytes(limits?.max_bytes ?? 2_000_000_000)} per export ·{" "}
            bundle deleted after {exports?.ttl_minutes ?? 60} min TTL · every
            export &amp; download is audited with SHA-256.
          </p>
        </div>
      )}

      {/* export register (doc 15.3 chain of custody) */}
      {!!exports?.items.length && (
        <div className="rounded-lg border border-zinc-800">
          <div className="border-b border-zinc-800 bg-zinc-950/70 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
            Export register (chain of custody)
          </div>
          <div className="divide-y divide-zinc-800/70">
            {exports.items.map((rec) => (
              <div key={rec.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs">
                <Badge variant="outline"
                       className={cn("text-[10px]",
                         rec.status === "ready" &&
                           "border-emerald-800 bg-emerald-950/50 text-emerald-300",
                         rec.status === "expired" &&
                           "border-zinc-800 bg-zinc-950/50 text-zinc-500",
                         rec.status === "failed" &&
                           "border-red-900 bg-red-950/40 text-red-300")}>
                  {rec.status}
                </Badge>
                <span className="text-zinc-300">{rec.actor}</span>
                <span className="text-zinc-600">{timeAgo(rec.created_at)}</span>
                <span className="max-w-[280px] truncate text-zinc-500"
                      title={rec.reason}>
                  “{rec.reason}”
                </span>
                <span className="text-zinc-600">
                  {rec.session_count} sess · {fmtBytes(rec.total_bytes)}
                </span>
                <span className="font-mono text-[10px] text-zinc-600"
                      title={rec.bundle_sha256 ?? undefined}>
                  {rec.status === "ready" ? shortSha(rec.bundle_sha256) : ""}
                </span>
                {rec.status === "ready" && canExport && (
                  DEMO_MODE ? (
                    <Button size="sm" variant="outline"
                            className="ml-auto h-6 border-zinc-700 px-2 text-[10px] text-zinc-400"
                            onClick={() => toast({
                              title: "Demo mode",
                              description: "bundle download is available in a live deployment" })}>
                      <Download className="mr-1 h-3 w-3" /> download
                    </Button>
                  ) : (
                    <a className="ml-auto"
                       href={pcapExportDownloadUrl(rec.id)}
                       download={rec.bundle_name ?? undefined}>
                      <Button size="sm" variant="outline"
                              className="h-6 border-zinc-700 px-2 text-[10px] text-zinc-300 hover:bg-zinc-800">
                        <Download className="mr-1 h-3 w-3" /> download
                      </Button>
                    </a>
                  )
                )}
                {rec.status === "failed" && (
                  <span className="max-w-[320px] truncate text-[10px] text-red-400/80"
                        title={rec.error ?? ""}>
                    {rec.error}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SessionRowView({ row, checked, onToggle }: {
  row: SessionRow;
  checked: boolean;
  onToggle: () => void;
}) {
  const meta = STATUS_META[row.pcap_status];
  const flow = `${row.source_ip ?? "?"} → ${row.destination_ip ?? "?"}${
    row.destination_port ? `:${row.destination_port}` : ""}`;
  const hint = [
    row.dns_query && `dns ${row.dns_query}`,
    row.tls_sni && `sni ${row.tls_sni}`,
    row.http_host && `host ${row.http_host}`,
    row.session_id && `session ${row.session_id}`,
  ].filter(Boolean).join(" · ");
  return (
    <tr className={cn("hover:bg-zinc-900/60", !checked && "opacity-90")}>
      <td className="px-3 py-1.5">
        <input type="checkbox" checked={checked} onChange={onToggle}
               className="h-3.5 w-3.5 accent-violet-600" />
      </td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[10px] text-zinc-400">
        {row["@timestamp"]?.slice(0, 19).replace("T", " ") ?? "-"}
      </td>
      <td className="px-3 py-1.5 text-zinc-400">{row.source_engine ?? "-"}</td>
      <td className="px-3 py-1.5">
        <div className="font-mono text-[11px] text-zinc-300">{flow}</div>
        {hint && <div className="truncate text-[10px] text-zinc-600">{hint}</div>}
      </td>
      <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums text-zinc-400">
        {fmtNumber(row.network_bytes ?? 0)}
      </td>
      <td className="px-3 py-1.5">
        <span title={row.pcap_note}>
          <Badge variant="outline" className={cn("text-[10px]", meta.cls)}>
            {meta.label}
          </Badge>
        </span>
      </td>
      <td className="px-3 py-1.5 text-right">
        {row.arkime_url && (
          <a href={row.arkime_url} target="_blank" rel="noreferrer"
             title="Open this session in the Arkime viewer (expression deep link)">
            <ExternalLink className="h-3.5 w-3.5 text-sky-400 hover:text-sky-300" />
          </a>
        )}
      </td>
    </tr>
  );
}
