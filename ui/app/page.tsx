"use client";

// NDR Console - application shell.
// Views: Dashboard, Threat Map, Topology, Alert Center, Event Search,
//        Assets, Reports, Sensors, Users, Audit.
// Demo mode renders the rich synthetic dataset; live mode talks to /backend.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  Activity, BellRing, Dice5, Dices, Dna, FileBarChart, FileCog, FlaskConical,
  Gauge, Globe2,
  KeyRound, LayoutDashboard, LogOut, Network, Radar, ScrollText, Search,
  Server, Settings, ShieldCheck, UserCog, Users, Crosshair, Waypoints, Rss,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { UsersView } from "@/components/ndr/admin";
import { ChangePasswordDialog } from "@/components/ndr/change-password";
import { AlertsView } from "@/components/ndr/alerts";
import { AssetsView } from "@/components/ndr/assets";
import { AuditView } from "@/components/ndr/audit";
import { DgaView } from "@/components/ndr/dga";
import { DnsExplorerView } from "@/components/ndr/dns-explorer";
import { GamblingView } from "@/components/ndr/gambling-view";
import { LiveTrafficWidget } from "@/components/ndr/live-traffic";
import { EventsView } from "@/components/ndr/events";
import { IncidentsView } from "@/components/ndr/incidents";
import { LoginView } from "@/components/ndr/login";
import { OverviewView } from "@/components/ndr/overview";
import { ReportsView } from "@/components/ndr/reports";
import { RolesView } from "@/components/ndr/roles";
import { RulesView } from "@/components/ndr/rules";
import { SensorsView } from "@/components/ndr/sensors";
import { SettingsView } from "@/components/ndr/settings";
import { ThreatIntelView } from "@/components/ndr/threat-intel";
import { ThreatMapView } from "@/components/ndr/threat-map";
import { TopologyView } from "@/components/ndr/topology";
import { fmtTime } from "@/components/ndr/shared";
import {
  DEMO_MODE, getIncidentStats, getRichOverview, getSettings, getThreatIntel,
  listAudit,
  listSensors, listUsers, login as apiLogin, logout as apiLogout, me,
  UnauthorizedError,
} from "@/lib/ndr/api";
import type {
  AuditRow, RichOverview, SessionUser, SensorRow, SystemSettings,
  ThreatIntelData, UserRow,
} from "@/lib/ndr/types";

type View =
  | "overview" | "incidents" | "alerts" | "dga" | "threatintel" | "events"
  | "threatmap" | "topology" | "reports" | "sensors" | "audit"
  | "rules" | "intelfeeds" | "assets" | "users" | "roles" | "settings"
  | "dns" | "gambling"; // v0.16.0: DNS Explorer (req 7/9) + Judi Online (req 18)

// v0.10 navigation: detection flow (Monitor/Detect/Investigate/Govern) is
// separated from platform administration (Configuration). Detection results
// (Threat Intel matches) stay in Detect; feed MANAGEMENT moved to
// Configuration together with Rule Manager, Assets, Users and Roles.
// v0.13.0: adminOnly entries are HIDDEN for non-admin roles (the old UI
// showed Users/Audit/Settings to everyone -> 403 / logout-loop on click)
const NAV: { id: View; label: string; icon: React.ElementType; group: string; adminOnly?: boolean }[] = [
  { id: "overview", label: "Dashboard", icon: LayoutDashboard, group: "Monitor" },
  { id: "incidents", label: "Incidents", icon: Waypoints, group: "Detect" },
  { id: "alerts", label: "Alert Center", icon: BellRing, group: "Detect" },
  // v0.12.8: dedicated DGA focus menu (lens over dga_suspected +
  // dns_nxdomain_burst alerts - no new detector)
  { id: "dga", label: "DGA Activity", icon: Dna, group: "Detect" },
  { id: "threatintel", label: "Threat Intel", icon: Crosshair, group: "Detect" },
  // v0.16.0 (req 18): watchlist Judi Online
  { id: "gambling", label: "Judi Online", icon: Dices, group: "Detect" },
  { id: "threatmap", label: "Threat Map", icon: Globe2, group: "Detect" },
  // v0.16.0 (req 7): DNS Explorer - resolved/gagal + transaksi lengkap
  { id: "dns", label: "DNS & TLS", icon: Globe2, group: "Investigate" },
  { id: "events", label: "Event Search", icon: Search, group: "Investigate" },
  { id: "topology", label: "Topology", icon: Network, group: "Investigate" },
  { id: "reports", label: "Reports", icon: FileBarChart, group: "Govern" },
  { id: "sensors", label: "Sensors", icon: Radar, group: "Govern" },
  { id: "audit", label: "Audit Log", icon: ScrollText, group: "Govern", adminOnly: true },
  { id: "rules", label: "Rule Manager", icon: FileCog, group: "Configuration" },
  { id: "intelfeeds", label: "Intel Feeds", icon: Rss, group: "Configuration" },
  { id: "assets", label: "Assets", icon: Server, group: "Configuration" },
  { id: "users", label: "Users", icon: Users, group: "Configuration", adminOnly: true },
  { id: "roles", label: "Roles", icon: UserCog, group: "Configuration" },
  { id: "settings", label: "Settings", icon: Settings, group: "Configuration", adminOnly: true },
];

export default function Home() {
  const { toast } = useToast();
  const [user, setUser] = useState<SessionUser | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [view, setView] = useState<View>("overview");

  const [rich, setRich] = useState<RichOverview | null>(null);
  const [richLoading, setRichLoading] = useState(true);
  const [richLoadError, setRichLoadError] = useState<string | null>(null);
  const [sensors, setSensors] = useState<SensorRow[]>([]);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [audit, setAudit] = useState<{ total: number; records: AuditRow[] }>({ total: 0, records: [] });
  const [tiData, setTiData] = useState<ThreatIntelData | null>(null);
  const [viewDataLoading, setViewDataLoading] = useState(true);
  const [clock, setClock] = useState<string>("");
  const [openIncidents, setOpenIncidents] = useState(0);
  // v0.12.9: cross-navigation Alert Center/DGA -> Threat Map is FOCUSED:
  // the map view renders ONLY the attack relationship of that alert
  // (incident subgraph or honest single-alert graph) instead of landing
  // on the heavy global/geographic map (user report).
  const [alertFocus, setAlertFocus] = useState<{
    alertId: string; nonce: number;
  } | null>(null);
  // v0.12.1: deep-link from Threat Intel match sheet -> Event Search (event_id filter)
  // v0.12.8: deep-link from Alert Center / DGA detail -> Event Search with
  // the alert's source/destination pair inside its own time window
  const [eventFocus, setEventFocus] = useState<{
    eventId?: string;
    ips?: { src?: string; dst?: string };
    timeFrom?: string;
    timeTo?: string;
    nonce: number;
  } | null>(null);
  // v0.12.8: deep-link from Alert Center -> Incidents detail
  const [incidentFocus, setIncidentFocus] = useState<{ id: string; nonce: number } | null>(null);
  // v0.11 system settings (name + branding)
  const [sysSettings, setSysSettings] = useState<SystemSettings | null>(null);

  const canEditAlerts = useMemo(() =>
    !!user && ["administrator", "security_engineer", "soc_analyst", "soc_lead"].includes(user.role),
  [user]);
  // ti_admin permission (doc 9.3): feed management restricted to these roles
  // v0.13.0: NAV visibility gate (administrator only for adminOnly items)
  const isAdmin = user?.role === "administrator";
  const canAdminTI = useMemo(() =>
    !!user && ["administrator", "security_engineer"].includes(user.role),
  [user]);
  // rule_admin: suricata rule enable/disable + update (same trust level)
  const canEditRules = canAdminTI;

  const refreshRich = useCallback(async () => {
    setRichLoading(true);
    try {
      const [r, incStats] = await Promise.all([
        getRichOverview(),
        getIncidentStats().catch(() => null),
      ]);
      setRich(r);
      setOpenIncidents(incStats?.open_total ?? 0);
      setRichLoadError(null);
    } catch (e) {
      setRichLoadError(e instanceof Error ? e.message : String(e));
      if (!(e instanceof UnauthorizedError)) {
        toast({ title: "Failed to load dashboard data", description: String(e), variant: "destructive" });
      }
    } finally {
      setRichLoading(false);
    }
  }, [toast]);

  const refreshViewData = useCallback(async (v: View) => {
    setViewDataLoading(true);
    try {
      if (v === "sensors") setSensors(await listSensors());
      if (v === "users") setUsers(await listUsers());
      if (v === "audit") setAudit(await listAudit());
      // Threat Intel results and Intel Feeds share one bundle (doc 9)
      if (v === "threatintel" || v === "intelfeeds") setTiData(await getThreatIntel());
    } catch (e) {
      if (e instanceof UnauthorizedError) setUser(null);
      else toast({ title: "Load failed", description: String(e), variant: "destructive" });
    } finally {
      setViewDataLoading(false);
    }
  }, [toast]);

  // session bootstrap
  useEffect(() => {
    (async () => {
      try {
        setUser(await me());
      } catch {
        setUser(null);
      } finally {
        setAuthChecked(true);
      }
    })();
  }, []);

  // data on login / view change
  useEffect(() => {
    if (!user) return;
    refreshRich();
    refreshViewData(view);
  }, [user, view, refreshRich, refreshViewData]);

  // v0.11: load system settings once after login (name + branding)
  useEffect(() => {
    if (!user) { setSysSettings(null); return; }
    getSettings().then(setSysSettings).catch(() => undefined);
  }, [user]);

  // v0.11 branding: console name (title) + favicon + document title
  useEffect(() => {
    if (!sysSettings) return;
    document.title = sysSettings.system.name;
    let link = document.querySelector<HTMLLinkElement>(
      "link[rel*='icon']");
    if (sysSettings.branding.favicon) {
      if (!link) {
        link = document.createElement("link");
        link.rel = "icon";
        document.head.appendChild(link);
      }
      link.href = sysSettings.branding.favicon;
    }
  }, [sysSettings]);

  // auto refresh dashboard data every 45s
  useEffect(() => {
    if (!user || view !== "overview") return;
    const t = setInterval(refreshRich, 45_000);
    return () => clearInterval(t);
  }, [user, view, refreshRich]);

  // auto refresh threat intel every 60s
  useEffect(() => {
    if (!user || (view !== "threatintel" && view !== "intelfeeds")) return;
    const t = setInterval(() => refreshViewData(view), 60_000);
    return () => clearInterval(t);
  }, [user, view, refreshViewData]);

  // header clock
  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString("en-GB", { hour12: false })), 1000);
    return () => clearInterval(t);
  }, []);

  // v0.12.2: change-password dialog state (forced after first login)
  const [pwOpen, setPwOpen] = useState(false);
  const [pwForced, setPwForced] = useState(false);

  async function handleLogin(username: string, password: string): Promise<string | null> {
    try {
      const u = await apiLogin(username, password);
      setUser(u);
      if (u.must_change_password) {
        setPwForced(true);
        setPwOpen(true);
      }
      toast({ title: "Signed in", description: `Welcome, ${u.username} (${u.role.replace("_", " ")})` });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Login failed";
    }
  }

  async function handleLogout() {
    await apiLogout();
    setUser(null);
    setView("overview");
  }

  if (!authChecked) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950">
        <div className="flex items-center gap-3 text-sm text-zinc-500">
          <ShieldCheck className="h-5 w-5 animate-pulse text-emerald-500" />
          Checking session...
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginView onLogin={handleLogin} demo={DEMO_MODE} />;
  }

  const groups = Array.from(new Set(NAV.map((n) => n.group)));

  return (
    <div className="flex min-h-screen bg-zinc-950 text-zinc-100">
      {/* sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-zinc-800/80 bg-zinc-900/40 backdrop-blur md:flex">
        <div className="flex items-center gap-2.5 px-4 py-4">
          {sysSettings?.branding.logo ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={sysSettings.branding.logo} alt="logo"
                 className="h-9 w-9 rounded-lg border border-zinc-800 object-contain" />
          ) : (
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-900 bg-emerald-950/60">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
            </div>
          )}
          <div>
            <div className="text-sm font-semibold tracking-tight">
              {sysSettings?.system.name ?? "NDR Console"}
            </div>
            <div className="text-[10px] text-zinc-500">
              {sysSettings?.system.tagline ?? "network detection & response"}
            </div>
          </div>
        </div>
        <Separator className="bg-zinc-800/70" />
        {/* v0.12.7: native overflow scroll (min-h-0 is REQUIRED inside a
            flex column, otherwise the nav cannot shrink and the bottom
            items get clipped on shorter screens - the Radix ScrollArea
            silently failed to scroll in that situation). */}
        <nav className="flex min-h-0 flex-1 flex-col overflow-y-auto overscroll-contain px-2 py-3 ndr-scroll-thin">
          {groups.map((g) => (
            <div key={g} className="mb-4">
              <div className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-widest text-zinc-600">{g}</div>
              {NAV.filter((n) => n.group === g && (!n.adminOnly || isAdmin)).map((n) => (
                <button key={n.id}
                        onClick={() => setView(n.id)}
                        className={`mb-0.5 flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors ${
                          view === n.id
                            ? "ndr-gloss font-medium text-sky-200"
                            : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
                        }`}>
                  <n.icon className="h-4 w-4" />
                  {n.label}
                  {n.id === "incidents" && !!openIncidents && view !== "incidents" && (
                    <span className="ml-auto rounded-full bg-red-950 px-1.5 py-0.5 text-[9px] font-semibold text-red-300">
                      {openIncidents}
                    </span>
                  )}
                  {n.id === "alerts" && !!rich?.new_alerts_today && view !== "alerts" && (
                    <span className="ml-auto rounded-full bg-red-950 px-1.5 py-0.5 text-[9px] font-semibold text-red-300">
                      {rich.new_alerts_today}
                    </span>
                  )}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="border-t border-zinc-800/70 p-3">
          <div className="mb-2 flex items-center justify-between rounded-md bg-zinc-900 px-2.5 py-2">
            <div className="min-w-0">
              <div className="truncate text-xs font-medium text-zinc-300">{user.username}</div>
              <div className="text-[10px] text-zinc-500">{user.role.replace("_", " ")}</div>
            </div>
            <div className="flex shrink-0 items-center gap-0.5">
              <Button size="icon" variant="ghost"
                      onClick={() => { setPwForced(false); setPwOpen(true); }}
                      className="h-7 w-7 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300"
                      title="Change password">
                <KeyRound className="h-3.5 w-3.5" />
              </Button>
              <Button size="icon" variant="ghost" onClick={handleLogout}
                      className="h-7 w-7 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300"
                      title="Sign out">
                <LogOut className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
          <div className="flex items-center justify-center gap-1.5 text-[10px] text-zinc-600">
            <FlaskConical className="h-3 w-3" />
            {DEMO_MODE ? "demo data - not connected to backend" : "live backend"}
          </div>
        </div>
      </aside>

      {/* main */}
      <div className="flex min-h-screen flex-1 flex-col md:pl-60">
        <header className="sticky top-0 z-20 border-b border-zinc-800/80 bg-zinc-950/90 backdrop-blur">
          <div className="flex h-14 items-center justify-between px-4 md:px-6">
            <div className="flex items-center gap-3">
              <ShieldCheck className="h-5 w-5 text-emerald-400 md:hidden" />
              <h2 className="text-sm font-semibold text-zinc-200">
                {NAV.find((n) => n.id === view)?.label}
              </h2>
              {rich && (
                <Badge variant="outline"
                       className="hidden border-emerald-900 bg-emerald-950/50 text-emerald-300 sm:inline-flex">
                  <Activity className="mr-1 h-3 w-3" />
                  {rich.health.status}
                </Badge>
              )}
              {rich?.health.pipeline.eps != null && (
                <Badge variant="outline" className="hidden border-zinc-800 text-zinc-400 lg:inline-flex">
                  <Gauge className="mr-1 h-3 w-3" />
                  {rich.health.pipeline.eps.toFixed(0)} eps
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-3 text-xs text-zinc-500">
              {rich?.health.pipeline.last_event_time && (
                <span className="hidden sm:inline">last event {fmtTime(rich.health.pipeline.last_event_time)}</span>
              )}
              <span className="font-mono tabular-nums text-zinc-400">{clock}</span>
            </div>
          </div>
          {/* mobile nav */}
          <div className="flex gap-1 overflow-x-auto border-t border-zinc-800/70 px-2 py-1.5 md:hidden">
            {NAV.filter((n) => !n.adminOnly || isAdmin).map((n) => (
              <button key={n.id} onClick={() => setView(n.id)}
                      className={`whitespace-nowrap rounded-md px-2.5 py-1.5 text-xs ${
                        view === n.id ? "ndr-gloss text-sky-200" : "text-zinc-400"
                      }`}>
                {n.label}
              </button>
            ))}
          </div>
        </header>

        <main className="flex-1 p-4 md:p-6">
          {view === "overview" && (
            <OverviewView rich={rich} loading={richLoading}
                          onOpenAlerts={() => setView("alerts")}
                          loadError={richLoadError}
                          onRetry={() => { void refreshRich(); }} />
          )}
          {view === "incidents" && (
            <IncidentsView canEdit={canEditAlerts}
                           focusIncidentId={incidentFocus?.id ?? null} />
          )}
          {view === "alerts" && (
            <AlertsView canEdit={canEditAlerts}
                      canApproveWhitelist={canAdminTI}
                        onOpenThreatMap={(a) => {
                          setView("threatmap");
                          setAlertFocus((f) => ({
                            alertId: a.alert_id,
                            nonce: (f?.nonce ?? 0) + 1,
                          }));
                        }}
                        onOpenIncident={(id) => {
                          setView("incidents");
                          setIncidentFocus((f) => ({ id, nonce: (f?.nonce ?? 0) + 1 }));
                        }}
                        onVerifyEvents={(req) => {
                          setView("events");
                          setEventFocus((f) => ({
                            ips: { src: req.src, dst: req.dst },
                            timeFrom: req.from,
                            timeTo: req.to,
                            nonce: (f?.nonce ?? 0) + 1,
                          }));
                        }} />
          )}
          {view === "dga" && (
            <DgaView canEdit={canEditAlerts}
                    canApproveWhitelist={canAdminTI}
                     onOpenThreatMap={(a) => {
                       setView("threatmap");
                       setAlertFocus((f) => ({
                         alertId: a.alert_id,
                         nonce: (f?.nonce ?? 0) + 1,
                       }));
                     }}
                     onOpenIncident={(id) => {
                       setView("incidents");
                       setIncidentFocus((f) => ({ id, nonce: (f?.nonce ?? 0) + 1 }));
                     }}
                     onVerifyEvents={(req) => {
                       setView("events");
                       setEventFocus((f) => ({
                         ips: { src: req.src, dst: req.dst },
                         timeFrom: req.from,
                         timeTo: req.to,
                         nonce: (f?.nonce ?? 0) + 1,
                       }));
                     }} />
          )}
          {/* v0.16.0 (req 7/9): DNS & TLS Explorer */}
          {view === "dns" && <DnsExplorerView />}
          {/* v0.16.0 (req 18): watchlist Judi Online */}
          {view === "gambling" && <GamblingView />}
          {view === "threatintel" && (
            <ThreatIntelView data={tiData} loading={viewDataLoading}
                             canAdmin={canAdminTI}
                             onOpenEvent={(eventId, eventTime) => {
                               setView("events");
                               setEventFocus((f) => ({
                                 eventId,
                                 timeFrom: eventTime
                                   ? new Date(new Date(eventTime).getTime() - 86_400_000).toISOString()
                                   : undefined,
                                 nonce: (f?.nonce ?? 0) + 1,
                               }));
                             }}
                             onRefresh={() => refreshViewData("threatintel")} />
          )}
          {view === "intelfeeds" && (
            <ThreatIntelView data={tiData} loading={viewDataLoading}
                             canAdmin={canAdminTI} section="feeds"
                             onRefresh={() => refreshViewData("intelfeeds")} />
          )}
          {view === "events" && <EventsView canSearch focus={eventFocus} />}
          {view === "threatmap" && (
            <ThreatMapView alertFocus={alertFocus}
                           onOpenIncident={(id) => {
                             setIncidentFocus((f) => ({ id, nonce: (f?.nonce ?? 0) + 1 }));
                             setView("incidents");
                           }} />
          )}
          {view === "rules" && (
            <RulesView canEdit={canEditRules} username={user.username} />
          )}
          {view === "topology" && (
            <TopologyView hosts={rich?.hosts ?? []} flows={rich?.flows ?? []}
                          externals={rich?.externals ?? []} zoneTraffic={rich?.zone_traffic ?? []} />
          )}
          {view === "assets" && (
            <AssetsView hosts={rich?.hosts ?? []} flows={rich?.flows ?? []} externals={rich?.externals ?? []} />
          )}
          {view === "reports" && <ReportsView rich={rich} />}
          {view === "sensors" && <SensorsView sensors={sensors} rich={rich} loading={viewDataLoading} />}
          {view === "users" && (
            <UsersView users={users} loading={viewDataLoading}
                       canManage={user.role === "administrator"}
                       currentUser={user.username}
                       onReload={() => refreshViewData("users")} />
          )}
          {view === "roles" && <RolesView />}
          {view === "settings" && (
            <SettingsView canManage={user.role === "administrator"} />
          )}
          {view === "audit" && <AuditView audit={audit} loading={viewDataLoading} />}
        </main>

        <footer className="mt-auto border-t border-zinc-800/70 px-6 py-3 text-center text-[11px] text-zinc-600">
          NDR Platform - detections are heuristics with evidence, not proof of compromise - retention {rich?.health.retention_days ?? 60} days
        </footer>
      </div>

      {/* v0.12.2: change own password (forced on first login / manual) */}
      {user && (
        <ChangePasswordDialog open={pwOpen} forced={pwForced} username={user.username}
                              onClose={() => setPwOpen(false)}
                              onChanged={() => {
                                setPwOpen(false);
                                setPwForced(false);
                                toast({ title: "Password changed",
                                        description: "All sessions were revoked - please sign in again." });
                                setUser(null);
                                setView("overview");
                              }} />
      )}
    </div>
  );
}
