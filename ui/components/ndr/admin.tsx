"use client";

// User management (v0.10): full CRUD over platform users.
// Backend enforces user_admin (administrator only) per endpoint - the UI
// guards are convenience, never the security boundary.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { Paginator, fmtTime } from "./shared";
import { Pencil, Plus, ShieldCheck, Trash2, UserPlus } from "lucide-react";
import { useMemo, useState } from "react";
import { createUser, deleteUser, updateUser } from "@/lib/ndr/api";
import type { Role, UserRow } from "@/lib/ndr/types";

const ROLES: Role[] = ["administrator", "security_engineer", "soc_analyst", "soc_lead", "auditor"];

export function UsersView({ users, loading, canManage, currentUser, onReload }: {
  users: UserRow[];
  loading: boolean;
  canManage: boolean;
  currentUser: string;
  onReload: () => void;
}) {
  const { toast } = useToast();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // create dialog
  const [addOpen, setAddOpen] = useState(false);
  const [addDraft, setAddDraft] = useState({
    username: "", full_name: "", role: "soc_analyst" as Role, password: "",
  });
  const [busy, setBusy] = useState(false);

  // edit dialog
  const [editTarget, setEditTarget] = useState<UserRow | null>(null);
  const [editDraft, setEditDraft] = useState({
    full_name: "", role: "soc_analyst" as Role, is_active: true, new_password: "",
  });

  const paged = useMemo(
    () => users.slice((page - 1) * pageSize, page * pageSize),
    [users, page, pageSize]);

  async function submitAdd() {
    if (!addDraft.username.trim()) {
      toast({ title: "Username required", variant: "destructive" });
      return;
    }
    if (addDraft.password.length < 10) {
      // v0.13.0: align the UI rule with the backend (min 10)
      toast({ title: "Password too short", description: "Initial password must be at least 10 characters", variant: "destructive" });
      return;
    }
    setBusy(true);
    try {
      const created = await createUser({
        username: addDraft.username.trim(),
        role: addDraft.role,
        full_name: addDraft.full_name.trim() || undefined,
        password: addDraft.password,
      });
      toast({
        title: "User created",
        description: `${created.username} (${created.role.replace("_", " ")}) must change the password at first login.`,
      });
      setAddOpen(false);
      setAddDraft({ username: "", full_name: "", role: "soc_analyst", password: "" });
      onReload();
    } catch (e) {
      toast({ title: "Create failed", description: String(e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  async function submitEdit() {
    if (!editTarget) return;
    setBusy(true);
    try {
      const updated = await updateUser(editTarget.id, {
        role: editDraft.role,
        full_name: editDraft.full_name.trim() || undefined,
        is_active: editDraft.is_active,
        new_password: editDraft.new_password || undefined,
      });
      toast({
        title: "User updated",
        description: `${updated.username} - role/password changes revoke existing sessions.`,
      });
      setEditTarget(null);
      onReload();
    } catch (e) {
      toast({ title: "Update failed", description: String(e), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  async function removeUser(u: UserRow) {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return;
    try {
      await deleteUser(u.id);
      toast({ title: "User deleted", description: u.username });
      onReload();
    } catch (e) {
      toast({ title: "Delete failed", description: String(e), variant: "destructive" });
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
            <ShieldCheck className="h-4 w-4 text-emerald-400" /> User management
          </h3>
          <p className="mt-0.5 text-xs text-zinc-500">
            RBAC is enforced in the backend per endpoint - hiding UI elements is never the only control.
            Role capabilities are listed on the Roles page.
          </p>
        </div>
        {canManage && (
          <Button size="sm" onClick={() => setAddOpen(true)}
                  className="bg-emerald-600 text-white hover:bg-emerald-500">
            <UserPlus className="mr-1.5 h-4 w-4" /> Add user
          </Button>
        )}
      </div>

      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
        {loading ? (
          <div className="space-y-2 p-6">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 bg-zinc-900" />)}</div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500">Username</TableHead>
                  <TableHead className="text-zinc-500">Role</TableHead>
                  <TableHead className="text-zinc-500">Full name</TableHead>
                  <TableHead className="text-zinc-500">Last login</TableHead>
                  <TableHead className="text-zinc-500">Created</TableHead>
                  <TableHead className="text-zinc-500">Flags</TableHead>
                  {canManage && <TableHead className="w-24 text-right text-zinc-500">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {paged.map((u) => (
                  <TableRow key={u.id} className="border-zinc-800/60">
                    <TableCell className="font-medium text-zinc-200">
                      {u.username}
                      {u.username === currentUser && (
                        <span className="ml-1.5 text-[10px] text-emerald-400">(you)</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-zinc-700 text-zinc-400">
                        {u.role.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-zinc-300">{u.full_name ?? "-"}</TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-zinc-400">{fmtTime(u.last_login_at)}</TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-zinc-500">{fmtTime(u.created_at)}</TableCell>
                    <TableCell>
                      <div className="flex gap-1.5">
                        {!u.is_active && (
                          <Badge variant="outline" className="border-red-900 bg-red-950/60 text-red-300">disabled</Badge>
                        )}
                        {u.must_change_password && (
                          <Badge variant="outline" className="border-amber-900 bg-amber-950/60 text-amber-300">must change password</Badge>
                        )}
                      </div>
                    </TableCell>
                    {canManage && (
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          <button title="Edit user"
                                  className="rounded border border-zinc-700 bg-zinc-950 p-1 text-zinc-400 transition-colors hover:border-sky-600 hover:text-sky-300"
                                  onClick={() => {
                                    setEditTarget(u);
                                    setEditDraft({
                                      full_name: u.full_name ?? "", role: u.role,
                                      is_active: u.is_active, new_password: "",
                                    });
                                  }}>
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            title={u.username === currentUser ? "You cannot delete your own account" : "Delete user"}
                            disabled={u.username === currentUser}
                            className="rounded border border-zinc-700 bg-zinc-950 p-1 text-zinc-400 transition-colors hover:border-red-600 hover:text-red-300 disabled:cursor-not-allowed disabled:opacity-40"
                            onClick={() => removeUser(u)}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
                {!paged.length && (
                  <TableRow className="border-zinc-800/60">
                    <TableCell colSpan={canManage ? 7 : 6} className="py-10 text-center text-sm text-zinc-500">No users</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
            <Paginator page={page} pageSize={pageSize} total={users.length}
                       onPage={setPage}
                       onPageSize={(s) => { setPageSize(s); setPage(1); }} />
          </>
        )}
      </div>

      {/* add user dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-zinc-100">
              <Plus className="h-4 w-4 text-emerald-400" /> Add user
            </DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-1">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="new-username">Username</Label>
                <Input id="new-username" value={addDraft.username}
                       onChange={(e) => setAddDraft((d) => ({ ...d, username: e.target.value }))}
                       className="border-zinc-800 bg-zinc-900 text-sm" />
              </div>
              <div className="space-y-1.5">
                <Label>Role</Label>
                <Select value={addDraft.role}
                        onValueChange={(v) => setAddDraft((d) => ({ ...d, role: v as Role }))}>
                  <SelectTrigger className="border-zinc-800 bg-zinc-900"><SelectValue /></SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    {ROLES.map((r) => (
                      <SelectItem key={r} value={r}>{r.replace("_", " ")}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="new-fullname">Full name</Label>
              <Input id="new-fullname" value={addDraft.full_name}
                     onChange={(e) => setAddDraft((d) => ({ ...d, full_name: e.target.value }))}
                     className="border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="new-password">Initial password (min 8 chars)</Label>
              <Input id="new-password" type="password" value={addDraft.password}
                     onChange={(e) => setAddDraft((d) => ({ ...d, password: e.target.value }))}
                     className="border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <p className="text-[11px] text-zinc-600">
              The user must change this password at first login (must_change_password flag).
              The action is recorded in the audit log; the password itself never is.
            </p>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setAddOpen(false)} className="text-zinc-400">Cancel</Button>
            <Button onClick={submitAdd} disabled={busy}
                    className="bg-emerald-600 text-white hover:bg-emerald-500">
              {busy ? "Creating..." : "Create user"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* edit user dialog */}
      <Dialog open={!!editTarget} onOpenChange={(open) => !open && setEditTarget(null)}>
        <DialogContent className="border-zinc-800 bg-zinc-950 sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">Edit user: {editTarget?.username}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-1">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Role</Label>
                <Select value={editDraft.role}
                        onValueChange={(v) => setEditDraft((d) => ({ ...d, role: v as Role }))}>
                  <SelectTrigger className="border-zinc-800 bg-zinc-900"><SelectValue /></SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    {ROLES.map((r) => (
                      <SelectItem key={r} value={r}>{r.replace("_", " ")}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Account</Label>
                <Select value={editDraft.is_active ? "active" : "disabled"}
                        onValueChange={(v) => setEditDraft((d) => ({ ...d, is_active: v === "active" }))}>
                  <SelectTrigger className="border-zinc-800 bg-zinc-900"><SelectValue /></SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    <SelectItem value="active">active</SelectItem>
                    <SelectItem value="disabled">disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="edit-fullname">Full name</Label>
              <Input id="edit-fullname" value={editDraft.full_name}
                     onChange={(e) => setEditDraft((d) => ({ ...d, full_name: e.target.value }))}
                     className="border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="edit-password">New password (optional)</Label>
              <Input id="edit-password" type="password" value={editDraft.new_password}
                     placeholder="leave empty to keep current password"
                     onChange={(e) => setEditDraft((d) => ({ ...d, new_password: e.target.value }))}
                     className="border-zinc-800 bg-zinc-900 text-sm" />
            </div>
            <p className="text-[11px] text-zinc-600">
              Role or password changes bump the token version: every existing session for
              this user is revoked and re-login is required. The last active administrator
              cannot be disabled or demoted into lockout.
            </p>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEditTarget(null)} className="text-zinc-400">Cancel</Button>
            <Button onClick={submitEdit} disabled={busy}
                    className="bg-emerald-600 text-white hover:bg-emerald-500">
              {busy ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
