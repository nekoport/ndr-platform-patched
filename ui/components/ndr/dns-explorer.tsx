"use client";

// DNS Explorer (v0.16.0 - requirement 7) + TLS Insights (R9).
// R7 compliance: Zeek dns.log memuat pasangan request+response LENGKAP
// dalam satu record - summary menampilkan rasio resolved (NOERROR+answer)
// vs gagal (NXDOMAIN/SERVFAIL/...), dan tabel transaksi per klien.

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { CheckCircle2, Globe2, Search, ShieldCheck, XCircle } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  getDnsExplorerSummary, getTlsSummary, searchDns,
} from "@/lib/ndr/api";
import type { DnsHit, DnsSummary, TlsSummary } from "@/lib/ndr/types";
import { RefreshControls } from "./refresh-controls";
import { Paginator, StatCard, fmtNumber, fmtTime } from "./shared";
import { cn } from "@/lib/utils";

const PAGE_SIZES = [25, 50, 100];

export function DnsExplorerView() {
  const { toast } = useToast();
  const [hours, setHours] = useState(24);
  const [summary, setSummary] = useState<DnsSummary | null>(null);
  const [tls, setTls] = useState<TlsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [rows, setRows] = useState<DnsHit[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1); // Paginator 1-based (shared.tsx)
  const [pageSize, setPageSize] = useState(50);
  const [needle, setNeedle] = useState("");
  const [rcode, setRcode] = useState("all");
  const [tab, setTab] = useState<"dns" | "tls">("dns");

  const loadSummary = useCallback(async (h: number) => {
    try {
      const [s, t] = await Promise.all([
        getDnsExplorerSummary(h),
        getTlsSummary(h).catch(() => null),
      ]);
      setSummary(s);
      setTls(t);
    } catch (e) {
      toast({
        title: "Gagal memuat ringkasan DNS",
        description: String(e), variant: "destructive",
      });
    }
  }, [toast]);

  const loadRows = useCallback(async () => {
    setLoading(true);
    try {
      const from = new Date(Date.now() - hours * 3_600_000).toISOString();
      const to = new Date().toISOString();
      const filter = needle.trim()
        ? { field: "dns.query", op: "include" as const, value: needle.trim() }
        : undefined;
      const body = {
        time_from: from, time_to: to, filter,
        size: pageSize, from: (page - 1) * pageSize,
        ...(rcode !== "all"
          ? { query: { term: { "dns.rcode": rcode } } }
          : {}),
      };
      // query + filter dikirim terpisah; kirim satu-duanya sesuai isi
      const payload: Parameters<typeof searchDns>[0] = { ...body };
      if (filter && rcode !== "all") {
        payload.query = undefined;
        payload.filter = { and: [
          { field: "dns.rcode", op: "is", value: rcode },
          filter,
        ] };
      }
      const res = await searchDns(payload);
      setRows(res.hits ?? []);
      setTotal(res.total ?? 0);
    } catch (e) {
      toast({
        title: "Gagal memuat transaksi DNS",
        description: String(e), variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [hours, needle, rcode, page, pageSize, toast]);

  useEffect(() => { void loadSummary(hours); }, [hours, loadSummary]);
  useEffect(() => { void loadRows(); },
    [loadRows]); // eslint-disable-line react-hooks/exhaustive-deps

  const resolvedPct = summary?.resolved_pct ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
            <Globe2 className="h-5 w-5 text-sky-400" /> DNS Explorer
          </h2>
          <p className="text-xs text-zinc-500">
            Transaksi DNS request+response lengkap dari zeek dns.log
            (req 7) + metadata TLS (req 9). Semua lewat guard alias
            ndr-zeek-dns-read.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="bg-zinc-900 border border-zinc-700 rounded-md text-xs px-2 py-1.5 text-zinc-300"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}>
            {[6, 24, 72, 168].map((h) => (
              <option key={h} value={h}>{h} jam</option>
            ))}
          </select>
          <RefreshControls storageKey="dns-explorer" onRefresh={() => {
            void loadSummary(hours);
            void loadRows();
          }} />
        </div>
      </div>

      {summary ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {/* v0.16.1 (P1-4): penyebut rasio = dokumen dengan response
              (dns.rcode), EKSAK - bukan lagi hits.total ter-cap 10.000
              yang membuat rasio 9133% mustahil. */}
          <StatCard title="Total dokumen DNS" value={fmtNumber(summary.total)}
                   sub={`${fmtNumber(summary.transactions)} dengan response${summary.no_response ? ` - ${fmtNumber(summary.no_response)} tanpa response` : ""}`}
                   tone="default" />
          <StatCard title="Berhasil resolve" value={fmtNumber(summary.resolved)}
                   sub={`${resolvedPct}% NOERROR dari ${fmtNumber(summary.transactions)} transaksi`} tone="ok" />
          <StatCard title="Gagal resolve" value={fmtNumber(summary.unresolved)}
                   sub="NXDOMAIN/SERVFAIL/dll" tone="alert" />
          <StatCard title="Domain teratas"
                   value={summary.top_queried[0]?.domain ?? "-"}
                   sub={`${fmtNumber(summary.top_queried[0]?.count ?? 0)} kali`}
                   tone="default" />
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-20" />)}
        </div>
      )}

      <div className="flex gap-2">
        <Button size="sm" variant={tab === "dns" ? "secondary" : "ghost"}
                onClick={() => setTab("dns")}>Transaksi DNS</Button>
        <Button size="sm" variant={tab === "tls" ? "secondary" : "ghost"}
                onClick={() => setTab("tls")}>TLS Insights</Button>
      </div>

      {tab === "dns" && (
        <>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <h3 className="text-xs font-medium text-zinc-400 mb-2">
                  Rcode breakdown {hours} jam
                </h3>
                <div className="space-y-1">
                  {summary?.rcodes?.slice(0, 8).map((r) => {
                    const max = summary.rcodes[0]?.count || 1;
                    return (
                      <div key={r.key} className="flex items-center gap-2">
                        <span className="w-20 text-xs text-zinc-400 font-mono">
                          {r.key}
                        </span>
                        <div className="flex-1 h-2 rounded bg-zinc-800 overflow-hidden">
                          <div className={cn("h-full",
                            r.key === "NOERROR"
                              ? "bg-emerald-500"
                              : "bg-rose-500/80")}
                               style={{ width: `${(r.count / max) * 100}%` }} />
                        </div>
                        <span className="text-xs text-zinc-400 w-12 text-right">
                          {fmtNumber(r.count)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
              <div>
                <h3 className="text-xs font-medium text-zinc-400 mb-2">
                  Klien teratas
                </h3>
                <div className="space-y-1">
                  {summary?.top_clients?.slice(0, 8).map((c) => (
                    <div key={c.ip} className="flex items-center justify-between
                                               text-xs font-mono text-zinc-300">
                      <span>{c.ip}</span>
                      <Badge variant="outline" className="text-zinc-400">
                        {fmtNumber(c.count)}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative flex-1 min-w-56">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-zinc-500" />
              <Input
                className="pl-8 bg-zinc-900 border-zinc-700"
                placeholder="Saring domain (include, case-insensitive)..."
                value={needle}
                onChange={(e) => { setNeedle(e.target.value); setPage(1); }} />
            </div>
            <select
              className="bg-zinc-900 border border-zinc-700 rounded-md text-xs px-2 py-2 text-zinc-300"
              value={rcode}
              onChange={(e) => { setRcode(e.target.value); setPage(1); }}>
              <option value="all">semua rcode</option>
              {(summary?.rcodes ?? []).map((r) => (
                <option key={r.key} value={r.key}>{r.key}</option>
              ))}
            </select>
          </div>

          <div className="rounded-xl border border-zinc-800 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-zinc-900">
                  <TableHead className="text-zinc-400">Waktu</TableHead>
                  <TableHead className="text-zinc-400">Klien</TableHead>
                  <TableHead className="text-zinc-400">Query</TableHead>
                  <TableHead className="text-zinc-400">Rcode</TableHead>
                  <TableHead className="text-zinc-400">Resolved</TableHead>
                  <TableHead className="text-zinc-400">Jawaban</TableHead>
                  <TableHead className="text-zinc-400">Campaign</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && rows.length === 0 && (
                  [...Array(6)].map((_, i) => (
                    <TableRow key={i}>
                      <TableCell colSpan={7}>
                        <Skeleton className="h-5" />
                      </TableCell>
                    </TableRow>
                  ))
                )}
                {!loading && rows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7}
                               className="text-center text-zinc-500 text-sm py-8">
                      Tidak ada transaksi DNS pada rentang ini.
                    </TableCell>
                  </TableRow>
                )}
                {rows.map((h) => (
                  <TableRow key={h.id} className="hover:bg-zinc-900/60">
                    <TableCell className="font-mono text-xs text-zinc-400">
                      {fmtTime(h["@timestamp"])}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {h.client ?? "-"}
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-72
                                         truncate" title={h.query ?? ""}>
                      {h.query ?? "-"}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline"
                             className={cn("font-mono",
                               h.rcode === "NOERROR"
                                 ? "text-emerald-400 border-emerald-500/30"
                                 : "text-rose-400 border-rose-500/30")}>
                        {h.rcode ?? "-"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {h.resolved
                        ? <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                        : <XCircle className="h-4 w-4 text-rose-400/70" />}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400">
                      {h.answer_count > 0
                        ? `${h.answer_count}: ${(h.answers ?? [])
                          .map((a) => (a as { data?: string })?.data)
                          .filter(Boolean).join(", ").slice(0, 60)}`
                        : "-"}
                    </TableCell>
                    <TableCell>
                      {h.campaign
                        ? <Badge className="bg-rose-500/15 text-rose-300
                                           border-rose-500/30 text-xs">
                            {h.campaign}
                          </Badge>
                        : "-"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <Paginator page={page} pageSize={pageSize} total={total}
                     onPage={setPage} onPageSize={(s) => {
                       setPageSize(s); setPage(1);
                     }} />
        </>
      )}

      {tab === "tls" && tls && (
        <div className="grid md:grid-cols-3 gap-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-400 mb-2 flex items-center gap-1">
              <ShieldCheck className="h-3.5 w-3.5" /> Versi TLS
            </h3>
            {tls.versions?.slice(0, 8).map((v) => (
              <div key={v.key} className="flex justify-between text-xs
                                          font-mono text-zinc-300 py-0.5">
                <span>{v.key}</span>
                <span className="text-zinc-500">{fmtNumber(v.count)}</span>
              </div>
            ))}
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-400 mb-2">
              JA3 teratas (fingerprint)
            </h3>
            {tls.top_ja3?.slice(0, 8).map((v) => (
              <div key={v.key} className="flex justify-between text-xs
                                          font-mono text-zinc-300 py-0.5">
                <span className="truncate max-w-32">{v.key}</span>
                <span className="text-zinc-500">{fmtNumber(v.count)}</span>
              </div>
            ))}
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-400 mb-2">
              Issuer sertifikat
            </h3>
            {tls.issuers?.slice(0, 8).map((v) => (
              <div key={v.key} className="flex justify-between text-xs
                                          text-zinc-300 py-0.5">
                <span className="truncate max-w-48">{v.key}</span>
                <span className="text-zinc-500 font-mono">
                  {fmtNumber(v.count)}
                </span>
              </div>
            ))}
          </div>
          <p className="md:col-span-3 text-xs text-zinc-500">
            Metadata saja - tanpa dekripsi (sesuai bunyi requirement 9):
            versi, JA3 fingerprint, SNI, dan issuer sertifikat.
          </p>
        </div>
      )}
    </div>
  );
}
