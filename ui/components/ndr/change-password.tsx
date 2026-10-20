"use client";

// Change-password dialog (v0.12.2).
//
// Two modes:
// - forced  : must_change_password=true returned by login (bootstrap admin
//             and users created with "must change password"). The dialog
//             cannot be dismissed until the password is rotated.
// - manual  : opened from the sidebar user block at any time.
//
// The backend revokes every session on success (token_version bump), so the
// caller is always returned to the login screen afterwards.

import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { KeyRound, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { changePassword } from "@/lib/ndr/api";

export function ChangePasswordDialog({ open, forced, username, onClose, onChanged }: {
  open: boolean;
  forced: boolean;
  username: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // matches backend ChangePasswordRequest: min_length=10
  const rulesOk = next.length >= 10 && next === confirm && next !== current;

  function reset() {
    setCurrent(""); setNext(""); setConfirm(""); setError(null); setBusy(false);
  }

  async function submit() {
    if (!rulesOk || busy) return;
    setBusy(true);
    setError(null);
    try {
      await changePassword(current, next);
      reset();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to change password");
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v && !forced) { reset(); onClose(); } }}>
      <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-sm"
                     onInteractOutside={(e) => forced && e.preventDefault()}
                     onEscapeKeyDown={(e) => forced && e.preventDefault()}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm text-zinc-100">
            <KeyRound className="h-4 w-4 text-emerald-400" />
            Change password
            <span className="font-mono text-xs font-normal text-zinc-500">{username}</span>
          </DialogTitle>
        </DialogHeader>

        {forced && (
          <div className="flex items-start gap-2 rounded-lg border border-amber-900/60 bg-amber-950/30 px-3 py-2 text-[11px] leading-relaxed text-amber-200">
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            Your account still uses the initial password. Choose a new
            password before continuing - all existing sessions are revoked
            after the change.
          </div>
        )}

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="cpw-current" className="text-xs text-zinc-400">Current password</Label>
            <Input id="cpw-current" type="password" autoComplete="current-password"
                   className="border-zinc-800 bg-zinc-900 text-sm"
                   value={current} onChange={(e) => setCurrent(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="cpw-next" className="text-xs text-zinc-400">
              New password <span className="text-zinc-600">(min 10 characters)</span>
            </Label>
            <Input id="cpw-next" type="password" autoComplete="new-password"
                   className="border-zinc-800 bg-zinc-900 text-sm"
                   value={next} onChange={(e) => setNext(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="cpw-confirm" className="text-xs text-zinc-400">Confirm new password</Label>
            <Input id="cpw-confirm" type="password" autoComplete="new-password"
                   className="border-zinc-800 bg-zinc-900 text-sm"
                   value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </div>

          {next.length > 0 && confirm.length > 0 && next !== confirm && (
            <p className="text-[11px] text-red-400">New passwords do not match.</p>
          )}
          {next.length > 0 && next.length < 10 && (
            <p className="text-[11px] text-amber-400">Password must be at least 10 characters.</p>
          )}
          {next.length >= 10 && next === current && (
            <p className="text-[11px] text-amber-400">New password must differ from the current one.</p>
          )}
          {error && (
            <p className="rounded border border-red-900/60 bg-red-950/40 px-2.5 py-1.5 text-[11px] text-red-300">
              {error}
            </p>
          )}
        </div>

        <DialogFooter className="gap-2">
          {!forced && (
            <Button variant="outline" size="sm" disabled={busy}
                    className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
                    onClick={() => { reset(); onClose(); }}>
              Cancel
            </Button>
          )}
          <Button size="sm" disabled={!rulesOk || busy}
                  className="bg-emerald-700 text-white hover:bg-emerald-600"
                  onClick={submit}>
            {busy ? "Changing..." : "Change password"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
