"use client";

// Role management (v0.10) - read-only RBAC matrix.
//
// The capability matrix is CODE-ENFORCED in the backend
// (api/app/security.py PERMISSIONS, exposed via GET /api/roles); this page
// renders the enforced truth so analysts can see who may do what. Role
// ASSIGNMENT happens per user on the Users page. The matrix is deliberate-
// ly not editable from the UI: changing it is a deployment decision
// (code review + audit), not a runtime toggle.

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getRoles } from "@/lib/ndr/api";
import { Check, Info, Minus, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import type { Role, RoleMatrix } from "@/lib/ndr/types";

const ROLE_ACCENT: Record<Role, string> = {
  administrator: "border-red-800 bg-red-950/40 text-red-200",
  security_engineer: "border-violet-800 bg-violet-950/40 text-violet-200",
  soc_lead: "border-orange-800 bg-orange-950/40 text-orange-200",
  soc_analyst: "border-sky-800 bg-sky-950/40 text-sky-200",
  auditor: "border-zinc-700 bg-zinc-900/60 text-zinc-300",
};

export function RolesView() {
  const [matrix, setMatrix] = useState<RoleMatrix | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    getRoles()
      .then((m) => { if (alive) setMatrix(m); })
      .catch((e) => { if (alive) setError(String(e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);

  if (loading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-24 bg-zinc-900" />
        <Skeleton className="h-96 bg-zinc-900" />
      </div>
    );
  }
  if (error || !matrix) {
    return (
      <div className="rounded-xl border border-red-900/60 bg-red-950/20 p-6 text-sm text-red-300">
        Failed to load role matrix: {error ?? "empty response"}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2.5 rounded-lg border border-sky-900/50 bg-sky-950/25 px-3.5 py-2.5">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
        <p className="text-xs leading-relaxed text-sky-200/90">
          <span className="font-semibold">Role-based access control (RBAC).</span>{" "}
          This matrix is the ENFORCED source of truth - the backend checks the
          capability on every endpoint before the handler runs, regardless of what
          the UI shows. Roles are assigned per user on the{" "}
          <span className="text-zinc-300">Configuration &rarr; Users</span> page.
          Changing the matrix itself is a code/deployment change (reviewed + audited),
          not a runtime toggle - by design (doc section 12).
        </p>
      </div>

      {/* role cards */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {matrix.roles.map((r) => (
          <Card key={r.role} className="border-zinc-800 bg-zinc-900/60">
            <CardHeader className="pb-1.5">
              <CardTitle className="flex items-center gap-2 text-sm">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                <span>{r.label}</span>
                <Badge variant="outline" className={`ml-auto text-[9px] ${ROLE_ACCENT[r.role]}`}>
                  {r.role}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs leading-relaxed text-zinc-400">{r.description}</p>
              <p className="mt-2 text-[10px] text-zinc-600">
                {matrix.capabilities.filter((c) => c.roles.includes(r.role)).length} of{" "}
                {matrix.capabilities.length} capabilities
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* capability matrix */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60">
        <div className="border-b border-zinc-800 px-4 py-3 text-sm font-medium text-zinc-200">
          Capability matrix
        </div>
        <Table>
          <TableHeader>
            <TableRow className="border-zinc-800 hover:bg-transparent">
              <TableHead className="text-zinc-500">Capability</TableHead>
              <TableHead className="text-zinc-500">What it allows</TableHead>
              {matrix.roles.map((r) => (
                <TableHead key={r.role} className="text-center text-zinc-500">
                  <div className="mx-auto w-20 truncate text-[10px]" title={r.label}>
                    {r.label.split(" ")[0]}
                  </div>
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {matrix.capabilities.map((c) => (
              <TableRow key={c.capability} className="border-zinc-800/60">
                <TableCell className="font-mono text-xs text-emerald-300">{c.capability}</TableCell>
                <TableCell className="text-xs text-zinc-400">{c.description}</TableCell>
                {matrix.roles.map((r) => {
                  const allowed = c.roles.includes(r.role);
                  return (
                    <TableCell key={r.role} className="text-center">
                      {allowed ? (
                        <Check className="mx-auto h-4 w-4 text-emerald-400" aria-label="allowed" />
                      ) : (
                        <Minus className="mx-auto h-4 w-4 text-zinc-700" aria-label="denied" />
                      )}
                    </TableCell>
                  );
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
