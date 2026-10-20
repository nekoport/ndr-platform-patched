"use client";

/**
 * v0.14.0 WhitelistDialog - create an alert-whitelist entry straight from
 * the alert the analyst is looking at (entry point agreed in the design
 * discussion). Entity + alert_type are prefilled from the alert; layer,
 * TTL, retroactive tagging and a mandatory reason are chosen here.
 *
 * Governance: analysts submit -> PENDING; admin/security_engineer entries
 * are self-approved ACTIVE instantly (audited). The dialog shows which
 * outcome to expect based on role.
 */

import { useMemo, useState } from "react";
import { Loader2, ShieldCheck, ShieldAlert } from "lucide-react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import type { AlertDoc, AllowEntityField, AllowLayer } from "@/lib/ndr/types";
import { createAlertAllowlist } from "@/lib/ndr/api";

const TTL_OPTIONS = [
  { value: "", label: "Permanent (until deleted)" },
  { value: "24", label: "24 hours" },
  { value: "720", label: "30 days" },
  { value: "2160", label: "90 days" },
];

export function WhitelistDialog({ alert, canApprove, onClose, onCreated }: {
  alert: AlertDoc | null;
  /** administrator / security_engineer -> entry is ACTIVE immediately. */
  canApprove: boolean;
  onClose: () => void;
  onCreated?: () => void;
}) {
  const { toast } = useToast();
  const [entityField, setEntityField] = useState<AllowEntityField>("dst_ip");
  const [pinSignature, setPinSignature] = useState(false);
  const [layer, setLayer] = useState<AllowLayer>("L1");
  const [ttl, setTtl] = useState("");
  const [reason, setReason] = useState("");
  const [retroactive, setRetroactive] = useState(false);
  const [busy, setBusy] = useState(false);

  const entities = useMemo(() => {
    if (!alert) return [];
    const opts: { field: AllowEntityField; value: string }[] = [];
    if (alert.source?.ip) opts.push({ field: "src_ip", value: alert.source.ip });
    if (alert.destination?.ip) opts.push({ field: "dst_ip", value: alert.destination.ip });
    for (const d of alert.dns_domains ?? []) {
      opts.push({ field: "dst_domain", value: `.${d.split(".").slice(-2).join(".")}` });
    }
    return opts;
  }, [alert]);

  const signature = alert?.top_rules?.[0]?.signature ?? null;

  // keep the chosen entity valid whenever the dialog opens for a new alert
  const effectiveField = entities.some((e) => e.field === entityField)
    ? entityField
    : (entities[0]?.field ?? "dst_ip");
  const effectiveValue = entities.find((e) => e.field === effectiveField)?.value ?? "";

  async function submit() {
    if (!alert || busy) return;
    if (reason.trim().length < 5) {
      toast({ title: "Reason required",
               description: "Document WHY this is a false positive (min 5 chars).",
               variant: "destructive" });
      return;
    }
    if (!effectiveValue) {
      toast({ title: "No whitelistable entity",
               description: "This alert carries no IP/domain to scope the entry.",
               variant: "destructive" });
      return;
    }
    setBusy(true);
    try {
      const entry = await createAlertAllowlist({
        alert_type: alert.alert_type,
        signature: pinSignature && signature ? signature : null,
        entity_field: effectiveField,
        entity_value: effectiveValue,
        layer,
        reason: reason.trim(),
        ttl_hours: ttl ? Number(ttl) : null,
        retroactive,
      });
      toast({
        title: entry.status === "active"
          ? "Whitelist entry ACTIVE"
          : "Whitelist entry submitted (pending approval)",
        description: entry.status === "active"
          ? `${entry.layer}: matching ${entry.alert_type} on ${entry.entity_value} is now silenced${entry.retro_tagged ? ` (${entry.retro_tagged} existing alerts tagged)` : ""}.`
          : "An administrator / security engineer must approve it before it takes effect.",
      });
      setReason("");
      setRetroactive(false);
      onCreated?.();
      onClose();
    } catch (e) {
      toast({ title: "Whitelist failed", description: String(e),
               variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={!!alert} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-h-[85vh] overflow-y-auto border-zinc-800 bg-zinc-950 sm:max-w-lg"
                     onInteractOutside={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm text-zinc-100">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            Whitelist similar detections
            <span className="font-mono text-xs font-normal text-zinc-500">
              {alert?.alert_type}
            </span>
          </DialogTitle>
        </DialogHeader>

        {canApprove ? (
          <p className="rounded-lg border border-emerald-900/50 bg-emerald-950/25 px-3 py-2 text-[11px] leading-relaxed text-emerald-200">
            Your role approves whitelist entries - this entry becomes ACTIVE
            immediately (self-approval is recorded in the audit log).
          </p>
        ) : (
          <p className="flex items-start gap-2 rounded-lg border border-amber-900/50 bg-amber-950/25 px-3 py-2 text-[11px] leading-relaxed text-amber-200">
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            Your entry goes to PENDING - an administrator or security
            engineer reviews it before it takes effect (two-man rule).
          </p>
        )}

        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-[11px] text-zinc-400">Scope (entity)</Label>
              <select
                value={effectiveField}
                onChange={(e) => setEntityField(e.target.value as AllowEntityField)}
                className="mt-1 h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 px-2 text-sm text-zinc-100"
              >
                {entities.map((o) => (
                  <option key={o.field} value={o.field}>
                    {o.field === "src_ip" ? "Source IP" : o.field === "dst_ip" ? "Destination IP" : "Domain"}
                  </option>
                ))}
              </select>
              <Input readOnly value={effectiveValue}
                     className="mt-1.5 border-zinc-800 bg-zinc-900 font-mono text-xs text-zinc-300" />
            </div>
            <div>
              <Label className="text-[11px] text-zinc-400">Enforcement layer</Label>
              <select
                value={layer}
                onChange={(e) => setLayer(e.target.value as AllowLayer)}
                className="mt-1 h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 px-2 text-sm text-zinc-100"
              >
                <option value="L1">L1 - tag &amp; keep (safer)</option>
                <option value="L0">L0 - never store the alert</option>
              </select>
              <p className="mt-1.5 text-[10px] leading-relaxed text-zinc-500">
                {layer === "L1"
                  ? "Alert is still recorded, tagged as suppressed, and kept out of the triage queue - full record preserved."
                  : "Matching alerts are NOT indexed at all (only a hit counter). Raw events are always untouched."}
              </p>
            </div>
          </div>

          {signature && (
            <label className="flex items-center gap-2 text-xs text-zinc-300">
              <input type="checkbox" checked={pinSignature}
                     onChange={(e) => setPinSignature(e.target.checked)}
                     className="h-3.5 w-3.5 accent-emerald-500" />
              Pin to signature <span className="font-mono text-zinc-400">&quot;{signature}&quot;</span>
              (unpinned = any signature of this detection type)
            </label>
          )}

          <div>
            <Label className="text-[11px] text-zinc-400">Expiry</Label>
            <select
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              className="mt-1 h-9 w-full rounded-md border border-zinc-800 bg-zinc-900 px-2 text-sm text-zinc-100"
            >
              {TTL_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>

          <div>
            <Label className="text-[11px] text-zinc-400">
              Reason (mandatory, audited)
            </Label>
            <Textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. verified with infra: 10.0.106.232 is our vulnerability scanner - periodic internal scans are expected"
              className="mt-1 min-h-20 border-zinc-800 bg-zinc-900 text-sm"
            />
          </div>

          <label className="flex items-start gap-2 text-xs text-zinc-300">
            <input type="checkbox" checked={retroactive}
                   onChange={(e) => setRetroactive(e.target.checked)}
                   className="mt-0.5 h-3.5 w-3.5 accent-emerald-500" />
            Also tag matching alerts from the last 7 days
            {layer === "L0" && " (L0 hides NEW alerts; retro tags existing ones as L1)"}
            {!canApprove && " (applies when an admin approves)"}
          </label>
        </div>

        <div className="flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={onClose}
                  className="border-zinc-700 text-zinc-300">
            Cancel
          </Button>
          <Button size="sm" onClick={submit} disabled={busy}
                  className="bg-emerald-600 text-white hover:bg-emerald-500">
            {busy && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
            Create whitelist entry
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
