"use client";

// System settings view (v0.11).
// Rename the console, custom logo/favicon branding, NTP configuration,
// network facts (interfaces / resolvers) and network diagnosis tools
// (ping / traceroute / dns / port). Mutations are administrator-only on
// the backend (system_admin capability) and audited; diagnosis is
// restricted to administrator / security_engineer (sensor_admin).

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { WhitelistPanel } from "./whitelist-panel";
import {
  Activity, Clock, Globe, Image as ImageIcon, Info, Network, PlayCircle,
  RotateCcw, Save, ServerCog, Stethoscope, Terminal, Upload,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  getNetworkInfo, getNtpStatus, getSettings, patchBranding, patchNetwork,
  patchNtp, patchSystemName, runDiagnosis,
} from "@/lib/ndr/api";
import type {
  DiagnoseResult, DiagnoseTool, NetworkConfig, NtpConfig, SystemSettings,
} from "@/lib/ndr/types";

const TIMEZONES = [
  "Asia/Jakarta", "Asia/Pontianak", "Asia/Makassar", "Asia/Jayapura",
  "Asia/Singapore", "Asia/Tokyo", "UTC", "Europe/London", "Europe/Berlin",
  "America/New_York", "America/Los_Angeles",
];

const TOOLS: { id: DiagnoseTool; label: string; hint: string }[] = [
  { id: "dns", label: "DNS resolve", hint: "socket getaddrinfo" },
  { id: "ping", label: "Ping", hint: "ICMP echo, 1-10 packets" },
  { id: "traceroute", label: "Traceroute", hint: "numeric, max 15 hops" },
  { id: "port", label: "TCP port check", hint: "connect with 3s timeout" },
];

async function fileToDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("read failed"));
    reader.readAsDataURL(file);
  });
}

export function SettingsView({ canManage }: { canManage: boolean }) {
  const { toast } = useToast();
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);

  // local drafts
  const [nameDraft, setNameDraft] = useState("");
  const [taglineDraft, setTaglineDraft] = useState("");
  const [ntpDraft, setNtpDraft] = useState<NtpConfig | null>(null);
  const [ntpServersText, setNtpServersText] = useState("");
  const [netDraft, setNetDraft] = useState<NetworkConfig | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [ntpOut, setNtpOut] = useState<string | null>(null);

  // diagnosis
  const [tool, setTool] = useState<DiagnoseTool>("dns");
  const [target, setTarget] = useState("localhost");
  const [port, setPort] = useState("443");
  const [diagRunning, setDiagRunning] = useState(false);
  const [diag, setDiag] = useState<DiagnoseResult | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const s = await getSettings();
      setSettings(s);
      setNameDraft(s.system.name);
      setTaglineDraft(s.system.tagline);
      setNtpDraft(s.ntp);
      setNtpServersText(s.ntp.servers.join(", "));
      setNetDraft(await getNetworkInfo());
    } catch (e) {
      toast({ title: "Failed to load settings", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { void refresh(); }, [refresh]);

  async function saveSystem() {
    if (busy) return;
    setBusy("system");
    try {
      await patchSystemName({ name: nameDraft.trim(), tagline: taglineDraft.trim() });
      toast({ title: "Console name updated", description: "applies on the next page render" });
      await refresh();
    } catch (e) {
      toast({ title: "Save failed", description: String(e), variant: "destructive" });
    } finally { setBusy(null); }
  }

  async function uploadLogo(file: File | null, kind: "logo" | "favicon") {
    if (busy) return;
    try {
      if (!file) {
        await patchBranding(kind === "logo" ? { reset_logo: true } : { reset_favicon: true });
        toast({ title: `${kind} reset to default` });
      } else {
        if (file.size > 300_000) {
          toast({ title: "File too large", description: "max 300 KB for branding images", variant: "destructive" });
          return;
        }
        const dataUrl = await fileToDataUrl(file);
        await patchBranding(kind === "logo"
          ? { logo_data_url: dataUrl } : { favicon_data_url: dataUrl });
        toast({ title: `${kind} updated`, description: file.name });
      }
      await refresh();
    } catch (e) {
      toast({ title: "Branding update failed", description: String(e), variant: "destructive" });
    }
  }

  async function saveNtp() {
    if (busy || !ntpDraft) return;
    setBusy("ntp");
    try {
      const servers = ntpServersText.split(",").map((s) => s.trim()).filter(Boolean);
      const updated = await patchNtp({ servers, timezone: ntpDraft.timezone, enabled: ntpDraft.enabled });
      setNtpDraft(updated);
      toast({ title: "NTP configuration saved" });
    } catch (e) {
      toast({ title: "Save failed", description: String(e), variant: "destructive" });
    } finally { setBusy(null); }
  }

  async function checkNtp() {
    if (busy) return;
    setBusy("ntpstatus");
    try {
      const res = await getNtpStatus();
      setNtpOut(`${res.tool ? `source: ${res.tool}` : "source: none available"}\n${res.output}`);
    } catch (e) {
      setNtpOut(`check failed: ${String(e)}`);
    } finally { setBusy(null); }
  }

  async function saveNetwork() {
    if (busy || !netDraft) return;
    setBusy("network");
    try {
      const res = await patchNetwork({
        hostname: netDraft.hostname.trim(),
        dns_servers: netDraft.dns_servers,
      });
      setNetDraft(res);
      toast({
        title: res.applied ? "Network settings applied" : "Network settings saved (partial)",
        description: res.notes?.join(" - ") || undefined,
        variant: res.applied ? "default" : "destructive",
      });
    } catch (e) {
      toast({ title: "Save failed", description: String(e), variant: "destructive" });
    } finally { setBusy(null); }
  }

  async function runDiag() {
    if (diagRunning) return;
    setDiagRunning(true);
    setDiag(null);
    try {
      const res = await runDiagnosis({
        tool, target: target.trim(),
        count: 4, port: tool === "port" ? Number(port) : null,
      });
      setDiag(res);
    } catch (e) {
      toast({ title: "Diagnosis failed", description: String(e), variant: "destructive" });
    } finally { setDiagRunning(false); }
  }

  if (loading || !settings || !ntpDraft || !netDraft) {
    return (
      <Card className="border-zinc-800 bg-zinc-900/50 p-8 text-center text-sm text-zinc-500">
        Loading settings...
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card className="border-sky-900/50 bg-sky-950/25 p-3">
        <div className="flex items-start gap-2 text-xs text-sky-200/90">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
          <p>
            <span className="font-semibold">System administration.</span> Renames,
            branding and NTP apply to the console itself; network facts are read
            from the sensor node and changes that require host access are reported
            honestly (no silent success). Every mutation is audited and restricted
            to the administrator role.
          </p>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* ---------------- system name ---------------- */}
        <Card className="border-zinc-800 bg-zinc-900/60 p-4">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-zinc-200">
            <Terminal className="h-4 w-4 text-emerald-400" /> System name
          </h3>
          <div className="grid gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="sys-name">Console name</Label>
              <Input id="sys-name" value={nameDraft} disabled={!canManage}
                     onChange={(e) => setNameDraft(e.target.value)}
                     className="border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="sys-tag">Tagline</Label>
              <Input id="sys-tag" value={taglineDraft} disabled={!canManage}
                     onChange={(e) => setTaglineDraft(e.target.value)}
                     className="border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" disabled={!canManage || busy === "system"}
                      onClick={() => void saveSystem()}
                      className="bg-emerald-800 text-emerald-100 hover:bg-emerald-700">
                <Save className="mr-1.5 h-3.5 w-3.5" />
                {busy === "system" ? "Saving..." : "Save"}
              </Button>
              <span className="text-[11px] text-zinc-600">
                API version {settings.version}
              </span>
            </div>
          </div>
        </Card>

        {/* ---------------- branding ---------------- */}
        <Card className="border-zinc-800 bg-zinc-900/60 p-4">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-zinc-200">
            <ImageIcon className="h-4 w-4 text-emerald-400" /> Logo & favicon
          </h3>
          <div className="grid gap-4 sm:grid-cols-2">
            {(["logo", "favicon"] as const).map((kind) => {
              const current = kind === "logo"
                ? settings.branding.logo : settings.branding.favicon;
              return (
                <div key={kind} className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
                  <div className="mb-2 flex h-16 items-center justify-center rounded bg-zinc-900">
                    {current ? (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img src={current} alt={`${kind} preview`}
                           className={` ${kind === "logo" ? "max-h-14" : "h-10 w-10 object-contain"}`} />
                    ) : (
                      <span className="text-[10px] text-zinc-600">default</span>
                    )}
                  </div>
                  <p className="mb-2 text-[11px] uppercase tracking-widest text-zinc-500">{kind}</p>
                  <div className="flex items-center gap-2">
                    <label className={canManage ? "cursor-pointer" : "pointer-events-none opacity-50"}>
                      <input type="file" accept="image/png,image/jpeg,image/webp,image/svg+xml,image/x-icon"
                             className="hidden" disabled={!canManage}
                             onChange={(e) => {
                               const f = e.target.files?.[0] ?? null;
                               if (f) void uploadLogo(f, kind);
                               e.target.value = "";
                             }} />
                      <span className="inline-flex items-center gap-1 rounded-md border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300 hover:bg-zinc-800">
                        <Upload className="h-3 w-3" /> Upload
                      </span>
                    </label>
                    <Button size="sm" variant="ghost" disabled={!canManage || !current}
                            onClick={() => void uploadLogo(null, kind)}
                            className="h-7 px-2 text-[11px] text-zinc-400 hover:bg-zinc-800">
                      <RotateCcw className="mr-1 h-3 w-3" /> Reset
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
          <p className="mt-2 text-[11px] text-zinc-600">
            PNG / JPEG / WebP / SVG / ICO - max 300 KB. The logo replaces the shield
            in the sidebar; the favicon is applied to the browser tab.
          </p>
        </Card>

        {/* ---------------- NTP ---------------- */}
        <Card className="border-zinc-800 bg-zinc-900/60 p-4">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-zinc-200">
            <Clock className="h-4 w-4 text-emerald-400" /> NTP time sync
          </h3>
          <div className="grid gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="ntp-servers">NTP servers (comma separated)</Label>
              <Input id="ntp-servers" value={ntpServersText} disabled={!canManage}
                     placeholder="time.google.com, id.pool.ntp.org"
                     onChange={(e) => setNtpServersText(e.target.value)}
                     className="border-zinc-800 bg-zinc-900 font-mono text-sm" />
            </div>
            <div className="grid grid-cols-2 items-end gap-3">
              <div className="space-y-1.5">
                <Label>Timezone</Label>
                <Select value={ntpDraft.timezone} disabled={!canManage}
                        onValueChange={(v) => setNtpDraft({ ...ntpDraft, timezone: v })}>
                  <SelectTrigger className="border-zinc-800 bg-zinc-900 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    {(TIMEZONES.includes(ntpDraft.timezone)
                      ? TIMEZONES : [ntpDraft.timezone, ...TIMEZONES]).map((tz) => (
                      <SelectItem key={tz} value={tz}>{tz}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-2 pb-1">
                <Switch id="ntp-enabled" checked={ntpDraft.enabled} disabled={!canManage}
                        onCheckedChange={(v) => setNtpDraft({ ...ntpDraft, enabled: v })} />
                <Label htmlFor="ntp-enabled" className="text-xs text-zinc-400">enabled</Label>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" disabled={!canManage || busy === "ntp"}
                      onClick={() => void saveNtp()}
                      className="bg-emerald-800 text-emerald-100 hover:bg-emerald-700">
                <Save className="mr-1.5 h-3.5 w-3.5" />
                {busy === "ntp" ? "Saving..." : "Save"}
              </Button>
              <Button size="sm" variant="outline" disabled={busy === "ntpstatus"}
                      onClick={() => void checkNtp()}
                      className="border-zinc-800 text-zinc-300 hover:bg-zinc-800">
                <Activity className="mr-1.5 h-3.5 w-3.5" />
                {busy === "ntpstatus" ? "Checking..." : "Check status"}
              </Button>
            </div>
            {ntpOut && (
              <pre className="max-h-32 overflow-auto whitespace-pre-wrap rounded border border-zinc-800 bg-black/60 p-2 font-mono text-[11px] text-emerald-300/90">
                {ntpOut}
              </pre>
            )}
          </div>
        </Card>

        {/* ---------------- network ---------------- */}
        <Card className="border-zinc-800 bg-zinc-900/60 p-4">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-zinc-200">
            <Network className="h-4 w-4 text-emerald-400" /> Network
          </h3>
          <div className="grid gap-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="net-host">Hostname</Label>
                <Input id="net-host" value={netDraft.hostname} disabled={!canManage}
                       onChange={(e) => setNetDraft({ ...netDraft, hostname: e.target.value })}
                       className="border-zinc-800 bg-zinc-900 font-mono text-sm" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="net-dns">DNS resolvers (comma separated)</Label>
                <Input id="net-dns" value={netDraft.dns_servers.join(", ")} disabled={!canManage}
                       onChange={(e) => setNetDraft({ ...netDraft,
                         dns_servers: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                       className="border-zinc-800 bg-zinc-900 font-mono text-sm" />
              </div>
            </div>
            <div className="overflow-hidden rounded border border-zinc-800">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 bg-zinc-950/60">
                    <TableHead className="h-8 text-[10px] uppercase tracking-widest text-zinc-500">Interface</TableHead>
                    <TableHead className="h-8 text-[10px] uppercase tracking-widest text-zinc-500">State</TableHead>
                    <TableHead className="h-8 text-[10px] uppercase tracking-widest text-zinc-500">Addresses</TableHead>
                    <TableHead className="h-8 text-[10px] uppercase tracking-widest text-zinc-500">MAC</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(netDraft.interfaces ?? []).map((it) => (
                    <TableRow key={it.name ?? "-"} className="border-zinc-800/60">
                      <TableCell className="py-1.5 font-mono text-xs text-zinc-200">{it.name}</TableCell>
                      <TableCell className="py-1.5">
                        <Badge variant="outline" className={`text-[10px] ${
                          it.state === "up"
                            ? "border-emerald-900 bg-emerald-950/60 text-emerald-300"
                            : "border-zinc-800 text-zinc-400"}`}>
                          {it.state}
                        </Badge>
                      </TableCell>
                      <TableCell className="py-1.5 font-mono text-[11px] text-zinc-400">
                        {it.addrs?.join(", ") || "-"}
                      </TableCell>
                      <TableCell className="py-1.5 font-mono text-[11px] text-zinc-500">
                        {it.mac ?? "-"}
                      </TableCell>
                    </TableRow>
                  ))}
                  {!netDraft.interfaces?.length && (
                    <TableRow><TableCell colSpan={4} className="py-3 text-center text-xs text-zinc-600">
                      no interfaces enumerated in this environment
                    </TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" disabled={!canManage || busy === "network"}
                      onClick={() => void saveNetwork()}
                      className="bg-emerald-800 text-emerald-100 hover:bg-emerald-700">
                <Save className="mr-1.5 h-3.5 w-3.5" />
                {busy === "network" ? "Saving..." : "Save"}
              </Button>
              <span className="text-[11px] text-zinc-600">
                system resolvers: {netDraft.system_dns?.join(", ") || "-"}
              </span>
            </div>
            {netDraft.notes?.length ? (
              <p className="text-[11px] text-amber-300/80">
                {netDraft.notes.join(" - ")}
              </p>
            ) : null}
          </div>
        </Card>
      </div>

      {/* ---------------- diagnosis ---------------- */}
      <Card className="border-zinc-800 bg-zinc-900/60 p-4">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-zinc-200">
          <Stethoscope className="h-4 w-4 text-emerald-400" /> Network diagnosis
          <span className="text-[11px] font-normal text-zinc-600">
            - runs from the sensor node; restricted to admin / engineer
          </span>
        </h3>
        <div className="flex flex-wrap items-end gap-2">
          <div className="w-44">
            <Label className="mb-1 text-[11px] text-zinc-500">Tool</Label>
            <Select value={tool} onValueChange={(v) => setTool(v as DiagnoseTool)}>
              <SelectTrigger className="border-zinc-800 bg-zinc-900 text-sm"><SelectValue /></SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900">
                {TOOLS.map((t) => (
                  <SelectItem key={t.id} value={t.id}>{t.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="w-64">
            <Label className="mb-1 text-[11px] text-zinc-500">Target (hostname / IP)</Label>
            <Input value={target}
                   onChange={(e) => setTarget(e.target.value)}
                   placeholder="8.8.8.8 or host.example.org"
                   className="border-zinc-800 bg-zinc-900 font-mono text-sm" />
          </div>
          {tool === "port" && (
            <div className="w-28">
              <Label className="mb-1 text-[11px] text-zinc-500">Port</Label>
              <Input type="number" min={1} max={65535} value={port}
                     onChange={(e) => setPort(e.target.value)}
                     className="border-zinc-800 bg-zinc-900 font-mono text-sm" />
            </div>
          )}
          <Button onClick={() => void runDiag()} disabled={diagRunning || !target.trim()}
                  className="bg-emerald-800 text-emerald-100 hover:bg-emerald-700">
            <PlayCircle className={`mr-1.5 h-4 w-4 ${diagRunning ? "animate-pulse" : ""}`} />
            {diagRunning ? "Running..." : "Run"}
          </Button>
          <p className="w-full text-[10px] text-zinc-600">
            {TOOLS.find((t) => t.id === tool)?.hint} - targets are validated
            (hostname/IP only) and executed with fixed argv, never a shell.
          </p>
        </div>
        {diag && (
          <div className="mt-3">
            <div className="mb-1 flex items-center gap-2 text-[11px]">
              <Globe className="h-3 w-3 text-zinc-500" />
              <span className="font-mono text-zinc-400">{diag.tool} {diag.target}</span>
              <Badge variant="outline" className={`text-[10px] ${
                diag.ok ? "border-emerald-900 bg-emerald-950/60 text-emerald-300"
                        : "border-red-900 bg-red-950/60 text-red-300"}`}>
                {diag.ok ? "ok" : "failed"}
              </Badge>
              <span className="ml-auto text-zinc-600">{new Date(diag.at).toLocaleTimeString("en-GB")}</span>
            </div>
            <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded border border-zinc-800 bg-black/60 p-2.5 font-mono text-[11px] leading-relaxed text-emerald-300/90">
              {diag.output}
            </pre>
          </div>
        )}
      </Card>

      {/* ---------------- v0.14.0: alert whitelist ---------------- */}
      <WhitelistPanel canApprove={canManage} />

      <div className="flex flex-wrap items-center gap-4 text-[11px] text-zinc-600">
        <span className="flex items-center gap-1.5">
          <ServerCog className="h-3.5 w-3.5" />
          settings persist in the system_settings table - audited with actor + timestamp
        </span>
      </div>
    </div>
  );
}
