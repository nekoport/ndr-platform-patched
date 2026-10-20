"use client";

// Assets view - host inventory with risk scores, filters, drilldown drawer,
// and (v0.10) a MANUAL ASSET REGISTRY.
//
// Data sources, clearly separated:
//   1. Discovered hosts - derived from traffic telemetry (Zeek/Suricata/
//      flow enrichment); read-only, they appear because traffic was seen.
//   2. Registered assets - manually added by the SOC. Alerts whose source
//      or destination IP matches a registered (or discovered) asset are
//      labeled with the hostname in Alert Center (asset-name enrichment).

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { HostDetailContent } from "./geo";
import { Sparkline, VizPanel } from "./charts";
import { Paginator, fmtBytes, fmtNumber, fmtTime, timeAgo } from "./shared";
import { Info, Pencil, Plus, Server, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { createAsset, deleteAsset, listAssets, updateAsset } from "@/lib/ndr/api";
import type { ExternalEntity, GeoFlow, HostAsset, RegisteredAsset } from "@/lib/ndr/types";
import { cn } from "@/lib/utils";

const RISK_BAR = (score: number) =>
  score >= 70 ? "#f87171" : score >= 45 ? "#fbbf24" : "#38bdf8";

const ZONES = ["dmz", "servers", "workstations", "iot", "management"];
const CRITS: RegisteredAsset["criticality"][] = ["low", "medium", "high", "critical"];

interface AssetDraft {
  ip: string; hostname: string; zone: string; role: string;
  criticality: RegisteredAsset["criticality"]; notes: string;
}
const EMPTY_DRAFT: AssetDraft = {
  ip: "", hostname: "", zone: "servers", role: "", criticality: "medium", notes: "",
};

export function AssetsView({ hosts, flows, externals }: {
  hosts: HostAsset[]; flows: GeoFlow[]; externals: ExternalEntity[];
}) {
  const { toast } = useToast();
  const [registry, setRegistry] = useState<RegisteredAsset[]>([]);
  const [registryLoading, setRegistryLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [editTarget, setEditTarget] = useState<RegisteredAsset | null>(null);
  const [draft, setDraft] = useState<AssetDraft>(EMPTY_DRAFT);
  const [busy, setBusy] = useState(false);

  // discovered-host table state
  const [zone, setZone] = useState("all");
  const [status, setStatus] = useState("all");
  const [keyword, setKeyword] = useState("");
  const [selected, setSelected] = useState<HostAsset | null>(null);
  const [hostPage, setHostPage] = useState(1);
  const [hostPageSize, setHostPageSize] = useState(10);
  const [regPage, setRegPage] = useState(1);
  const [regPageSize, setRegPageSize] = useState(10);

  const loadRegistry = async () => {
    setRegistryLoading(true);
    try {
      setRegistry(await listAssets());
    } catch (e) {
      toast({ title: "Failed to load asset registry", description: String(e), variant: "destructive" });
    } finally {
      setRegistryLoading(false);
    }
  };
  useEffect(() => { loadRegistry(); }, []);

  async function submitAsset() {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(draft.ip.trim())) {
      toast({ title: "Invalid IP", description: "Enter a valid IPv4 address", variant: "destructive" });
      return;
    }
    if (!draft.hostname.trim() || !draft.role.trim()) {
      toast({ title: "Missing fields", description: "Hostname and role are required", variant: "destructive" });
      return;
    }
    setBusy(true);
    try {
      if (editTarget) {
        await updateAsset(editTarget.id, {
          hostname: draft.hostname.trim(), zone: draft.zone, role: draft.role.trim(),
          criticality: draft.criticality, notes: draft.notes.trim() || undefined,
        });
        toast({ title: "Asset updated", description: `${draft.hostname} (${draft.ip})` });
      } else {
        await createAsset({
          ip: draft.ip.trim(), hostname: draft.hostname.trim(), zone: draft.zone,
          role: draft.role.trim(), criticality: draft.criticality,
          notes: draft.notes.trim() || undefined,
        });
        toast({
          title: "Asset registered",
          description: `Alerts from/to ${draft.hostname} will now show its name`,
        });
      }
      setShowAdd(false);
      setEditTarget(null);
      setDraft(EMPTY_DRAFT);
      await loadRegistry();
    } catch (e) {
      toast({ title: editTarget ? "Update failed" : "Registration failed",
              description: String(e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  async function removeAsset(a: RegisteredAsset) {
    if (!confirm(`Remove ${a.hostname} (${a.ip}) from the asset registry?`)) return;
    try {
      await deleteAsset(a.id);
      toast({ title: "Asset removed" });
      await loadRegistry();
    } catch (e) {
      toast({ title: "Delete failed", description: String(e), variant: "destructive" });
    }
  }

  const filtered = useMemo(() => hosts.filter((h) => {
    if (zone !== "all" && h.zone !== zone) return false;
    if (status !== "all" && h.status !== status) return false;
    if (keyword) {
      const kw = keyword.toLowerCase();
      if (!h.hostname.includes(kw) && !h.ip.includes(kw) && !h.role.toLowerCase().includes(kw)) return false;
    }
    return true;
  }).sort((a, b) => b.risk_score - a.risk_score), [hosts, zone, status, keyword]);

  const pagedHosts = useMemo(
    () => filtered.slice((hostPage - 1) * hostPageSize, hostPage * hostPageSize),
    [filtered, hostPage, hostPageSize]);
  const pagedRegistry = useMemo(
    () => registry.slice((regPage - 1) * regPageSize, regPage * regPageSize),
    [registry, regPage, regPageSize]);

  const counts = useMemo(() => ({
    total: hosts.length,
    atRisk: hosts.filter((h) => h.status === "at_risk").length,
    watch: hosts.filter((h) => h.status === "watch").length,
    healthy: hosts.filter((h) => h.status === "healthy").length,
    critical: hosts.filter((h) => h.criticality === "critical").length,
  }), [hosts]);

  const zoneCounts = useMemo(() => {
    const m = new Map<string, number>();
    hosts.forEach((h) => m.set(h.zone, (m.get(h.zone) ?? 0) + 1));
    return Array.from(m.entries());
  }, [hosts]);

  return (
    <div className="space-y-4">
      {/* data-source explanation */}
      <div className="flex items-start gap-2.5 rounded-lg border border-sky-900/50 bg-sky-950/25 px-3.5 py-2.5">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
        <p className="text-xs leading-relaxed text-sky-200/90">
          <span className="font-semibold">Where does this data come from?</span>{" "}
          <span className="text-zinc-300">Discovered hosts</span> are derived automatically
          from observed traffic (Zeek/Suricata/flow telemetry enrichment) - a host appears
          because it communicated on the network. <span className="text-zinc-300">Registered
          assets</span> are added manually below. Once registered, every alert whose source
          or destination IP matches the asset is labeled with its hostname in Alert Center,
          so alerts on known machines are immediately recognizable.
        </p>
      </div>

      {/* summary strip */}
      <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-6">
        <SumCard label="Discovered hosts" value={String(counts.total)} />
        <SumCard label="Critical assets" value={String(counts.critical)} tone="warn" />
        <SumCard label="At risk" value={String(counts.atRisk)} tone="alert" />
        <SumCard label="Watch" value={String(counts.watch)} tone="warn" />
        <SumCard label="Healthy" value={String(counts.healthy)} tone="ok" />
        <SumCard label="Registered (manual)" value={String(registry.length)} />
      </div>

      {/* ============ manual asset registry ============ */}
      <div className="rounded-xl border border-emerald-900/40 bg-emerald-950/10 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="flex items-center gap-2 text-sm font-semibold text-emerald-200">
              <Server className="h-4 w-4 text-emerald-400" /> Manual asset registry
            </h3>
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Machines you register here are recognized across the platform: alert
              enrichment in Alert Center, host context in investigations.
            </p>
          </div>
          <Button size="sm" onClick={() => { setDraft(EMPTY_DRAFT); setEditTarget(null); setShowAdd(true); }}
                  className="bg-emerald-600 text-white hover:bg-emerald-500">
            <Plus className="mr-1 h-4 w-4" /> Add asset
          </Button>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="text-zinc-500">Hostname</TableHead>
                <TableHead className="text-zinc-500">IP</TableHead>
                <TableHead className="text-zinc-500">Zone</TableHead>
                <TableHead className="text-zinc-500">Role</TableHead>
                <TableHead className="text-zinc-500">Criticality</TableHead>
                <TableHead className="text-zinc-500">Notes</TableHead>
                <TableHead className="text-zinc-500">Registered</TableHead>
                <TableHead className="w-20 text-right text-zinc-500">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {registryLoading ? (
                <TableRow><TableCell colSpan={8} className="py-8 text-center text-sm text-zinc-500">Loading registry...</TableCell></TableRow>
              ) : pagedRegistry.map((a) => (
                <TableRow key={a.id} className="border-zinc-800/60">
                  <TableCell className="font-mono text-xs font-medium text-zinc-100">{a.hostname}</TableCell>
                  <TableCell className="font-mono text-xs text-zinc-300">{a.ip}</TableCell>
                  <TableCell><Badge variant="outline" className="border-zinc-700 text-[10px] capitalize text-zinc-400">{a.zone}</Badge></TableCell>
                  <TableCell className="max-w-52 truncate text-xs text-zinc-400">{a.role}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={cn("text-[10px] capitalize",
                      a.criticality === "critical" ? "border-red-800 bg-red-950/50 text-red-300"
                      : a.criticality === "high" ? "border-orange-800 bg-orange-950/50 text-orange-300"
                      : a.criticality === "medium" ? "border-amber-800 bg-amber-950/40 text-amber-300"
                      : "border-zinc-700 text-zinc-400")}>
                      {a.criticality}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-64 truncate text-xs text-zinc-500">{a.notes ?? "-"}</TableCell>
                  <TableCell className="whitespace-nowrap text-[11px] text-zinc-500"
                             title={`by ${a.created_by ?? "unknown"}`}>
                    {timeAgo(a.created_at)}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-1">
                      <button title="Edit asset"
                              className="rounded border border-zinc-700 bg-zinc-950 p-1 text-zinc-400 transition-colors hover:border-sky-600 hover:text-sky-300"
                              onClick={() => {
                                setEditTarget(a);
                                setDraft({
                                  ip: a.ip, hostname: a.hostname, zone: a.zone, role: a.role,
                                  criticality: a.criticality, notes: a.notes ?? "",
                                });
                                setShowAdd(true);
                              }}>
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button title="Remove asset"
                              className="rounded border border-zinc-700 bg-zinc-950 p-1 text-zinc-400 transition-colors hover:border-red-600 hover:text-red-300"
                              onClick={() => removeAsset(a)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {!registryLoading && !pagedRegistry.length && (
                <TableRow><TableCell colSpan={8} className="py-8 text-center text-sm text-zinc-500">
                  No manually registered assets yet - click &quot;Add asset&quot; to register one.
                </TableCell></TableRow>
              )}
            </TableBody>
          </Table>
          <Paginator page={regPage} pageSize={regPageSize} total={registry.length}
                     onPage={setRegPage}
                     onPageSize={(s) => { setRegPageSize(s); setRegPage(1); }} />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-4">
        <VizPanel title="Assets by zone" icon={<Server className="h-4 w-4 text-emerald-400" />} sub="discovered hosts" className="lg:col-span-1">
          <div className="space-y-3">
            {zoneCounts.map(([z, n]) => (
              <div key={z}>
                <div className="mb-1 flex justify-between text-xs">
                  <span className="capitalize text-zinc-400">{z}</span>
                  <span className="tabular-nums text-zinc-300">{n}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-zinc-800">
                  <div className="h-full rounded-full bg-emerald-500/70 transition-all duration-700"
                       style={{ width: `${(n / counts.total) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </VizPanel>

        <div className="space-y-3 lg:col-span-3">
          {/* filters */}
          <div className="flex flex-col gap-2 md:flex-row">
            <Input placeholder="Search hostname, IP or role..." value={keyword}
                   onChange={(e) => setKeyword(e.target.value)}
                   className="border-zinc-800 bg-zinc-900 text-zinc-200 placeholder:text-zinc-600" />
            <Select value={zone} onValueChange={setZone}>
              <SelectTrigger className="border-zinc-800 bg-zinc-900 text-zinc-300 md:w-40">
                <SelectValue placeholder="Zone" />
              </SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
                <SelectItem value="all">All zones</SelectItem>
                {ZONES.map((z) => (
                  <SelectItem key={z} value={z} className="capitalize">{z}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger className="border-zinc-800 bg-zinc-900 text-zinc-300 md:w-40">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900 text-zinc-300">
                <SelectItem value="all">All statuses</SelectItem>
                {["healthy", "watch", "at_risk"].map((s) => (
                  <SelectItem key={s} value={s}>{s.replace("_", " ")}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
            <ScrollArea className="whitespace-nowrap">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-zinc-500">Host</TableHead>
                    <TableHead className="text-zinc-500">Zone</TableHead>
                    <TableHead className="text-zinc-500">Role</TableHead>
                    <TableHead className="text-zinc-500">Risk</TableHead>
                    <TableHead className="text-zinc-500">Trend 24h</TableHead>
                    <TableHead className="text-right text-zinc-500">In/Out</TableHead>
                    <TableHead className="text-right text-zinc-500">Conns</TableHead>
                    <TableHead className="text-right text-zinc-500">Alerts</TableHead>
                    <TableHead className="text-zinc-500">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pagedHosts.map((h) => (
                    <TableRow key={h.ip} className="cursor-pointer border-zinc-800/60 hover:bg-zinc-800/40"
                              onClick={() => setSelected(h)}>
                      <TableCell>
                        <div className="font-mono text-xs font-medium text-zinc-200">{h.hostname}</div>
                        <div className="font-mono text-[10px] text-zinc-600">{h.ip}</div>
                      </TableCell>
                      <TableCell><Badge variant="outline" className="border-zinc-700 text-[10px] capitalize text-zinc-400">{h.zone}</Badge></TableCell>
                      <TableCell className="max-w-52 truncate text-xs text-zinc-400">{h.role}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-14 overflow-hidden rounded-full bg-zinc-800">
                            <div className="h-full rounded-full" style={{ width: `${h.risk_score}%`, background: RISK_BAR(h.risk_score) }} />
                          </div>
                          <span className="tabular-nums text-xs text-zinc-300">{h.risk_score}</span>
                        </div>
                      </TableCell>
                      <TableCell className="w-24"><Sparkline data={h.traffic_24h} color={RISK_BAR(h.risk_score)} height={24} /></TableCell>
                      <TableCell className="whitespace-nowrap text-right font-mono text-[11px] text-zinc-400">
                        {fmtBytes(h.bytes_in)} / {fmtBytes(h.bytes_out)}
                      </TableCell>
                      <TableCell className="text-right tabular-nums text-xs text-zinc-300">{fmtNumber(h.conns_24h)}</TableCell>
                      <TableCell className={cn("text-right tabular-nums text-xs", h.alerts_24h > 0 ? "text-red-300" : "text-zinc-500")}>
                        {h.alerts_24h}
                      </TableCell>
                      <TableCell>
                        <span className={cn("inline-flex items-center gap-1.5 text-[11px] capitalize",
                          h.status === "at_risk" ? "text-red-300" : h.status === "watch" ? "text-amber-300" : "text-emerald-300")}>
                          <span className={cn("h-1.5 w-1.5 rounded-full",
                            h.status === "at_risk" ? "animate-pulse bg-red-400" : h.status === "watch" ? "bg-amber-400" : "bg-emerald-400")} />
                          {h.status.replace("_", " ")}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                  {!pagedHosts.length && (
                    <TableRow className="border-zinc-800/60">
                      <TableCell colSpan={9} className="py-10 text-center text-sm text-zinc-500">
                        No assets match the current filters
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
            <Paginator page={hostPage} pageSize={hostPageSize} total={filtered.length}
                       onPage={setHostPage}
                       onPageSize={(s) => { setHostPageSize(s); setHostPage(1); }} />
          </div>
        </div>
      </div>

      {/* add/edit dialog */}
      <Dialog open={showAdd} onOpenChange={(open) => { if (!open) { setShowAdd(false); setEditTarget(null); } }}>
        <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">
              {editTarget ? "Edit registered asset" : "Register asset"}
            </DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-1">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="asset-ip">IP address</Label>
                <Input id="asset-ip" value={draft.ip} placeholder="192.168.2.30"
                       disabled={!!editTarget}
                       onChange={(e) => setDraft((d) => ({ ...d, ip: e.target.value }))}
                       className="border-zinc-800 bg-zinc-900 font-mono text-sm" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="asset-hostname">Hostname</Label>
                <Input id="asset-hostname" value={draft.hostname} placeholder="vault-app-01"
                       onChange={(e) => setDraft((d) => ({ ...d, hostname: e.target.value }))}
                       className="border-zinc-800 bg-zinc-900 font-mono text-sm" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Zone</Label>
                <Select value={draft.zone} onValueChange={(v) => setDraft((d) => ({ ...d, zone: v }))}>
                  <SelectTrigger className="border-zinc-800 bg-zinc-900"><SelectValue /></SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    {ZONES.map((z) => <SelectItem key={z} value={z} className="capitalize">{z}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Criticality</Label>
                <Select value={draft.criticality}
                        onValueChange={(v) => setDraft((d) => ({ ...d, criticality: v as AssetDraft["criticality"] }))}>
                  <SelectTrigger className="border-zinc-800 bg-zinc-900"><SelectValue /></SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    {CRITS.map((c) => <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="asset-role">Role / description</Label>
              <Input id="asset-role" value={draft.role} placeholder="Payment vault application"
                     onChange={(e) => setDraft((d) => ({ ...d, role: e.target.value }))}
                     className="border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="asset-notes">Notes (optional)</Label>
              <Textarea id="asset-notes" value={draft.notes}
                        placeholder="Owner, change window, compliance scope..."
                        onChange={(e) => setDraft((d) => ({ ...d, notes: e.target.value }))}
                        className="min-h-16 border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <p className="text-[11px] text-zinc-600">
              After registration, alerts referencing this IP immediately display the
              hostname in Alert Center (source/destination enrichment).
            </p>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => { setShowAdd(false); setEditTarget(null); }}
                    className="text-zinc-400">Cancel</Button>
            <Button onClick={submitAsset} disabled={busy}
                    className="bg-emerald-600 text-white hover:bg-emerald-500">
              {busy ? "Saving..." : editTarget ? "Save changes" : "Register asset"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* host detail drawer (discovered hosts) */}
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
                  <Badge variant="outline" className="border-zinc-700 text-zinc-400">{selected.criticality}</Badge>
                  <Badge variant="outline" className="border-sky-900 text-[10px] text-sky-300">discovered</Badge>
                </div>
                <SheetTitle className="text-left text-lg text-zinc-100">
                  {selected.hostname} <span className="font-mono text-sm font-normal text-zinc-500">{selected.ip}</span>
                </SheetTitle>
                <p className="text-[10px] text-zinc-600">derived from traffic telemetry - profile updated continuously</p>
              </SheetHeader>
              <div className="px-4 pb-8">
                <HostDetailContent host={selected} flows={flows} externals={externals} />
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function SumCard({ label, value, tone }: { label: string; value: string; tone?: "ok" | "warn" | "alert" }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
      <div className={cn("mt-0.5 text-lg font-semibold tabular-nums",
        tone === "alert" ? "text-red-300" : tone === "warn" ? "text-amber-300" : tone === "ok" ? "text-emerald-300" : "text-zinc-100")}>
        {value}
      </div>
    </div>
  );
}
