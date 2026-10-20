"use client";

/**
 * v0.14.0 WhitelistPanel - manage alert-whitelist entries (Settings).
 * List + approve/reject (two-man rule) + extend TTL + delete, with hit
 * counters so the operator sees how much noise each entry eats.
 */

import { useCallback, useEffect, useState } from "react";
import { Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { RefreshControls } from "./refresh-controls";
import type { AllowEntry, AllowStatus } from "@/lib/ndr/types";
import {
  approveAlertAllowlist, deleteAlertAllowlist, extendAlertAllowlist,
  listAlertAllowlist, rejectAlertAllowlist,
} from "@/lib/ndr/api";

const STATUS_STYLES: Record<AllowStatus, string> = {
  active: "border-emerald-800 bg-emerald-950/40 text-emerald-300",
  pending: "border-amber-800 bg-amber-950/40 text-amber-300",
  expired: "border-zinc-700 bg-zinc-900 text-zinc-400",
  rejected: "border-red-900 bg-red-950/30 text-red-400",
};

const STATUS_FILTERS: { value: AllowStatus | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "active", label: "Active" },
  { value: "pending", label: "Pending" },
  { value: "expired", label: "Expired" },
  { value: "rejected", label: "Rejected" },
];

export function WhitelistPanel({ canApprove }: { canApprove: boolean }) {
  const { toast } = useToast();
  const [entries, setEntries] = useState<AllowEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<AllowStatus | "all">("all");
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setEntries(await listAlertAllowlist(
        status === "all" ? undefined : { status }));
    } catch (e) {
      toast({ title: "Failed to load whitelist",
               description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }, [status, toast]);

  useEffect(() => { void load(); }, [load]);

  async function act(id: number, fn: () => Promise<unknown>, okMsg: string) {
    setBusyId(id);
    try {
      await fn();
      toast({ title: okMsg });
      await load();
    } catch (e) {
      toast({ title: "Action failed", description: String(e),
               variant: "destructive" });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border-zinc-800 bg-zinc-900/50 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-emerald-400" />
        <h3 className="text-sm font-semibold text-zinc-100">
          Alert whitelist
        </h3>
        <span className="text-[11px] text-zinc-500">
          recurring false positives from legitimate internal tooling - raw
          events are never touched
        </span>
        <div className="ml-auto flex items-center gap-2">
          <div className="flex gap-1">
            {STATUS_FILTERS.map((f) => (
              <button
                key={f.value}
                onClick={() => setStatus(f.value)}
                className={`rounded-md px-2 py-1 text-[11px] transition-colors ${
                  status === f.value
                    ? "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300"}`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <RefreshControls storageKey="whitelist" onRefresh={() => { void load(); }}
                            loading={loading} compact />
        </div>
      </div>

      {loading ? (
        <div className="flex h-24 items-center justify-center text-sm text-zinc-500">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading entries...
        </div>
      ) : entries.length === 0 ? (
        <div className="rounded-lg border border-dashed border-zinc-800 px-4 py-6 text-center text-xs text-zinc-500">
          No whitelist entries yet. Create them from Alert Center
          &rarr; open an alert &rarr; &quot;Whitelist similar detections&hellip;&quot;.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-zinc-800 text-[10px] uppercase tracking-wider text-zinc-500">
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Detection</th>
                <th className="py-2 pr-3">Scope</th>
                <th className="py-2 pr-3">Layer</th>
                <th className="py-2 pr-3">Hits</th>
                <th className="py-2 pr-3">By / approved</th>
                <th className="py-2 pr-3">Expires</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-zinc-900 align-top">
                  <td className="py-2 pr-3">
                    <Badge variant="outline"
                           className={`text-[10px] ${STATUS_STYLES[e.status]}`}>
                      {e.status}
                    </Badge>
                  </td>
                  <td className="py-2 pr-3 font-mono text-[11px] text-zinc-300">
                    {e.alert_type}
                    {e.signature && (
                      <div className="text-[10px] text-zinc-500">
                        sig: {e.signature}
                      </div>
                    )}
                  </td>
                  <td className="py-2 pr-3 font-mono text-[11px] text-zinc-300">
                    <span className="text-zinc-500">{e.entity_field} =</span>{" "}
                    {e.entity_value}
                  </td>
                  <td className="py-2 pr-3">
                    <span className={e.layer === "L0"
                      ? "font-semibold text-orange-300" : "text-sky-300"}>
                      {e.layer}
                    </span>
                  </td>
                  <td className="py-2 pr-3 tabular-nums text-zinc-300">
                    {e.hit_count}
                  </td>
                  <td className="py-2 pr-3 text-[11px] text-zinc-400">
                    {e.created_by ?? "-"}
                    {e.approved_by && (
                      <div className="text-[10px] text-zinc-500">
                        approved: {e.approved_by}
                      </div>
                    )}
                  </td>
                  <td className="py-2 pr-3 text-[11px] text-zinc-400">
                    {e.expires_at
                      ? new Date(e.expires_at).toLocaleDateString()
                      : "never"}
                  </td>
                  <td className="py-2 pr-3">
                    <div className="flex flex-wrap gap-1.5">
                      {canApprove && e.status === "pending" && (
                        <>
                          <Button size="sm" variant="outline"
                                  disabled={busyId === e.id}
                                  className="h-6 border-emerald-800 px-2 text-[10px] text-emerald-300"
                                  onClick={() => act(e.id,
                                    () => approveAlertAllowlist(e.id),
                                    "Entry approved + active")}>
                            Approve
                          </Button>
                          <Button size="sm" variant="outline"
                                  disabled={busyId === e.id}
                                  className="h-6 border-red-900 px-2 text-[10px] text-red-300"
                                  onClick={() => act(e.id,
                                    () => rejectAlertAllowlist(e.id),
                                    "Entry rejected")}>
                            Reject
                          </Button>
                        </>
                      )}
                      {canApprove && (e.status === "expired"
                        || e.status === "active") && e.expires_at && (
                        <Button size="sm" variant="outline"
                                disabled={busyId === e.id}
                                className="h-6 border-zinc-700 px-2 text-[10px] text-zinc-300"
                                onClick={() => act(e.id,
                                  () => extendAlertAllowlist(e.id, 30),
                                  "Entry extended by 30 days")}>
                          +30 d
                        </Button>
                      )}
                      {canApprove && (
                        <Button size="sm" variant="outline"
                                disabled={busyId === e.id}
                                className="h-6 border-red-900 px-2 text-[10px] text-red-300"
                                onClick={() => {
                                  if (!window.confirm(
                                    "Delete this whitelist entry? Matching alerts will alert again."))
                                    return;
                                  void act(e.id,
                                    () => deleteAlertAllowlist(e.id),
                                    "Entry deleted");
                                }}>
                          Delete
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-3 text-[10px] leading-relaxed text-zinc-600">
        L0 = matching alerts are never indexed (counter only). L1 = alerts are
        indexed but tagged suppressed and kept out of the default triage queue.
        Deleted/expired entries immediately stop suppressing. Every change is
        audited (actor + timestamp + reason).
      </p>
    </Card>
  );
}
