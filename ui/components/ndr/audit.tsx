"use client";

// Audit Log - searchable record of every application action.

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StatusBadge, Paginator, fmtTime } from "./shared";
import { MiniBar } from "./charts";
import { ScrollText } from "lucide-react";
import { useMemo, useState } from "react";
import type { AuditRow } from "@/lib/ndr/types";

export function AuditView({ audit, loading }: {
  audit: { total: number; records: AuditRow[] };
  loading: boolean;
}) {
  const [action, setAction] = useState("all");
  const [result, setResult] = useState("all");
  const [keyword, setKeyword] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const actions = useMemo(
    () => Array.from(new Set(audit.records.map((r) => r.action))),
    [audit.records]);

  const filtered = useMemo(() => audit.records.filter((r) => {
    if (action !== "all" && r.action !== action) return false;
    if (result !== "all" && r.result !== result) return false;
    if (keyword) {
      const kw = keyword.toLowerCase();
      const hay = `${r.actor} ${r.target_id ?? ""} ${r.source_ip ?? ""} ${r.action}`.toLowerCase();
      if (!hay.includes(kw)) return false;
    }
    return true;
  }), [audit.records, action, result, keyword]);

  const byAction = useMemo(() => {
    const m = new Map<string, number>();
    audit.records.forEach((r) => m.set(r.action, (m.get(r.action) ?? 0) + 1));
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [audit.records]);

  const paged = useMemo(
    () => filtered.slice((page - 1) * pageSize, page * pageSize),
    [filtered, page, pageSize]);

  const failures = audit.records.filter((r) => r.result !== "success").length;

  return (
    <div className="space-y-4">
      {/* stats */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Card className="border-zinc-800 bg-zinc-900/60 px-4 py-3">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500">Total records</div>
          <div className="mt-0.5 text-xl font-semibold tabular-nums text-zinc-100">{audit.total}</div>
        </Card>
        <Card className="border-zinc-800 bg-zinc-900/60 px-4 py-3">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500">Non-success results</div>
          <div className={`mt-0.5 text-xl font-semibold tabular-nums ${failures ? "text-red-300" : "text-emerald-300"}`}>{failures}</div>
        </Card>
        <Card className="border-zinc-800 bg-zinc-900/60 px-4 py-3 sm:col-span-2">
          <div className="mb-1.5 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-zinc-500">
            <ScrollText className="h-3 w-3" /> Top actions
          </div>
          <div className="space-y-1">
            {byAction.map(([a, n]) => (
              <div key={a} className="flex items-center gap-2">
                <span className="w-28 shrink-0 truncate font-mono text-[10px] text-zinc-400">{a}</span>
                <MiniBar value={n} max={byAction[0][1]} color="#60a5fa" />
                <span className="w-6 shrink-0 text-right text-[10px] tabular-nums text-zinc-500">{n}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* filters */}
      <div className="flex flex-col gap-2 md:flex-row">
        <Input placeholder="Search actor, target, IP..." value={keyword} onChange={(e) => setKeyword(e.target.value)}
               className="border-zinc-800 bg-zinc-900 text-zinc-200 placeholder:text-zinc-600" />
        <Select value={action} onValueChange={setAction}>
          <SelectTrigger className="border-zinc-800 bg-zinc-900 text-zinc-300 md:w-48">
            <SelectValue placeholder="Action" />
          </SelectTrigger>
          <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
            <SelectItem value="all">All actions</SelectItem>
            {actions.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={result} onValueChange={setResult}>
          <SelectTrigger className="border-zinc-800 bg-zinc-900 text-zinc-300 md:w-36">
            <SelectValue placeholder="Result" />
          </SelectTrigger>
          <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
            <SelectItem value="all">All results</SelectItem>
            {["success", "failure", "denied"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      {/* table */}
      <Card className="border-zinc-800 bg-zinc-900/60">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-zinc-300">Application audit log</CardTitle>
          <p className="text-xs text-zinc-500">
            Every search, status change, and administrative action is recorded server-side. Records are append-only.
          </p>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-6">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 bg-zinc-900" />)}</div>
          ) : (
            <ScrollArea className="whitespace-nowrap">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-zinc-500">Time</TableHead>
                    <TableHead className="text-zinc-500">Actor</TableHead>
                    <TableHead className="text-zinc-500">Action</TableHead>
                    <TableHead className="text-zinc-500">Target</TableHead>
                    <TableHead className="text-zinc-500">Source IP</TableHead>
                    <TableHead className="text-zinc-500">Result</TableHead>
                    <TableHead className="text-zinc-500">Detail</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paged.map((r) => (
                    <TableRow key={r.id} className="border-zinc-800/60">
                      <TableCell className="whitespace-nowrap text-xs text-zinc-400">{fmtTime(r.occurred_at)}</TableCell>
                      <TableCell className="text-sm text-zinc-200">
                        {r.actor}
                        {r.actor_role && <span className="ml-1.5 text-[10px] text-zinc-600">{r.actor_role}</span>}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-300">{r.action}</TableCell>
                      <TableCell className="max-w-[220px] truncate font-mono text-xs text-zinc-500">
                        {r.target_type ? `${r.target_type}:${r.target_id ?? ""}` : "-"}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-500">{r.source_ip ?? "-"}</TableCell>
                      <TableCell><StatusBadge status={r.result} /></TableCell>
                      <TableCell className="max-w-[220px] truncate font-mono text-[10px] text-zinc-600">
                        {r.detail ? JSON.stringify(r.detail) : "-"}
                      </TableCell>
                    </TableRow>
                  ))}
                  {!filtered.length && (
                    <TableRow className="border-zinc-800/60">
                      <TableCell colSpan={7} className="py-10 text-center text-sm text-zinc-500">No audit records match filters</TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
          )}
          {!loading && (
            <Paginator page={page} pageSize={pageSize} total={filtered.length}
                       onPage={setPage}
                       onPageSize={(s) => { setPageSize(s); setPage(1); }} />
          )}
        </CardContent>
      </Card>

      <div className="flex items-center justify-center gap-2 text-[11px] text-zinc-600">
        <Badge variant="outline" className="border-zinc-800 text-zinc-600">immutability note</Badge>
        Audit records are append-only and outside user write scope; deletion requires database-level intervention and is logged in OS journals.
      </div>
    </div>
  );
}
