"use client";

// Custom Filter Builder (v0.16.0 - requirement 5).
// Membangun AST filter (and/or/not + is/is_one/include/exclude/cidr)
// yang dikirim ke API sebagai JSON - BUKAN string query, sehingga
// injeksi mustahil. Whitelist field/op dicerminkan dari backend
// app/filters.py (ALERT_FILTER_FIELDS); backend TETAP memvalidasi ulang
// (defense in depth), UI hanya mencegah kesalahan pengguna.

import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  ListTree, Plus, Trash2, Wand2,
} from "lucide-react";
import { useState } from "react";
import type { FilterAst, FilterGroup, FilterLeaf, FilterOp } from "@/lib/ndr/types";

// field -> op yang diizinkan (cermin ALERT_FILTER_FIELDS backend)
const FIELDS: { field: string; label: string; ops: FilterOp[]; type:
  "string" | "number" | "list" | "cidr" }[] = [
  { field: "severity", label: "Severity", ops: ["is", "is_one", "exclude"], type: "list" },
  { field: "status", label: "Status", ops: ["is", "is_one", "exclude"], type: "list" },
  { field: "outcome", label: "Verdict (outcome)", ops: ["is", "is_one", "exclude"], type: "list" },
  { field: "attack_status", label: "Attack status (tender)", ops: ["is", "is_one", "exclude"], type: "list" },
  { field: "detection_engine", label: "Engine deteksi", ops: ["is", "is_one", "exclude"], type: "list" },
  { field: "alert_type", label: "Alert type", ops: ["is", "is_one", "exclude"], type: "string" },
  { field: "campaign", label: "Campaign", ops: ["is", "is_one", "exclude"], type: "string" },
  { field: "kill_chain.stage", label: "Kill chain stage", ops: ["is", "is_one", "exclude"], type: "string" },
  { field: "cve", label: "CVE", ops: ["is", "is_one", "exclude"], type: "string" },
  { field: "dns_domains", label: "Domain DNS (alert)", ops: ["is", "is_one", "include", "exclude"], type: "string" },
  { field: "network.protocol", label: "Protocol", ops: ["is", "is_one", "exclude"], type: "string" },
  { field: "network.transport", label: "Transport", ops: ["is", "is_one", "exclude"], type: "string" },
  { field: "source.ip", label: "IP sumber", ops: ["is", "is_one", "exclude", "cidr"], type: "cidr" },
  { field: "destination.ip", label: "IP tujuan", ops: ["is", "is_one", "exclude", "cidr"], type: "cidr" },
  { field: "top_rules.signature", label: "Signature (top rule)", ops: ["is", "is_one", "include", "exclude"], type: "string" },
  { field: "top_rules.signature_id", label: "Signature ID (SID)", ops: ["is", "is_one", "exclude"], type: "string" },
  { field: "title", label: "Judul alert", ops: ["include"], type: "string" },
  { field: "sensor_id", label: "Sensor", ops: ["is"], type: "string" },
];

const STATUS_OPTIONS = ["new", "acknowledged", "in_progress", "closed",
  "false_positive"];
const ATTACK_STATUS_OPTIONS = ["attack_successful", "attempt", "failure",
  "indeterminate"];
const ENGINE_OPTIONS = ["signature", "behaviour", "intel"];
const SEV_OPTIONS = ["critical", "high", "medium", "low", "informational"];

const OP_LABEL: Record<FilterOp, string> = {
  is: "is (sama dengan)",
  is_one: "is one (salah satu dari)",
  include: "include (mengandung)",
  exclude: "not / exclude (bukan)",
  gt: ">", gte: ">=", lt: "<", lte: "<=", cidr: "CIDR",
};

interface RowState {
  id: number;
  field: string;
  op: FilterOp;
  value: string;   // teks; list dipisah koma
}

let rowSeq = 1;

/**
 * v0.16.1 (P0-3): normalisasi AST dari sumber mana pun (dialog, state,
 * deep-link) - elemen null/tak-valid dibuang SEBELUM dipetakan. Bug live
 * 2026-10-22: array berisi null membuat `.map` membaca 'field' dari null
 * dan SELURUH halaman Alert Center crash (error boundary).
 */
export function sanitizeFilterAst(ast: FilterAst | null | undefined): FilterAst | null {
  if (!ast || typeof ast !== "object") return null;
  const cleanLeaf = (l: unknown): FilterLeaf | null => {
    if (!l || typeof l !== "object") return null;
    const leaf = l as FilterLeaf;
    if (!leaf.field || typeof leaf.field !== "string") return null;
    if (leaf.value === undefined || leaf.value === null) return null;
    if (Array.isArray(leaf.value) && !leaf.value.length) return null;
    return leaf;
  };
  if ("and" in ast) {
    const leaves = (ast.and ?? []).map(cleanLeaf).filter(Boolean) as FilterLeaf[];
    return leaves.length ? { and: leaves } : null;
  }
  if ("or" in ast) {
    const leaves = (ast.or ?? []).map(cleanLeaf).filter(Boolean) as FilterLeaf[];
    return leaves.length ? { or: leaves } : null;
  }
  if ("not" in ast) {
    const inner = sanitizeFilterAst(ast.not as FilterAst);
    return inner ? { not: inner } : null;
  }
  return cleanLeaf(ast);
}

function fieldDef(field: string) {
  return FIELDS.find((f) => f.field === field);
}

function rowToLeaf(r: RowState): FilterLeaf | null {
  const def = fieldDef(r.field);
  if (!def) return null;
  const v = r.value.trim();
  if (!v && r.op !== "exclude") return null;
  if (r.op === "is_one") {
    const list = v.split(",").map((s) => s.trim()).filter(Boolean);
    if (!list.length) return null;
    return { field: r.field, op: "is_one", value: list };
  }
  if (r.op === "exclude") {
    if (!v) return null;
    const list = v.includes(",")
      ? v.split(",").map((s) => s.trim()).filter(Boolean)
      : v;
    return { field: r.field, op: "exclude", value: list };
  }
  return { field: r.field, op: r.op, value: v };
}

export function FilterBuilderDialog({
  open, onOpenChange, initial, onApply,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  initial?: FilterAst | null;
  /** Dipanggil dengan AST final (null = filter dibersihkan). */
  onApply: (ast: FilterAst | null) => void;
}) {
  const [glue, setGlue] = useState<"and" | "or">("and");
  const [rows, setRows] = useState<RowState[]>(() => {
    // initial AST flat (hanya dukung daftar leaf top-level) -> rows
    // v0.16.1 (P0-3): initial dinormalisasi dulu (filter(Boolean)) sehingga
    // elemen null tidak pernah mencapai `.map` pembaca leaf.field.
    const safe = sanitizeFilterAst(initial ?? null);
    const flat = safe && "and" in (safe as Record<string, unknown>)
      ? (safe as { and?: FilterLeaf[] }).and
      : safe && "or" in (safe as Record<string, unknown>)
        ? (safe as { or?: FilterLeaf[] }).or
        : safe
          ? [safe as FilterLeaf]
          : [];
    const arr = (Array.isArray(flat) ? flat : flat ? [flat] : [])
      .filter(Boolean) as FilterLeaf[];
    return arr.map((l) => {
      const leaf = l as FilterLeaf;
      rowSeq += 1;
      return {
        id: rowSeq,
        field: leaf.field || "severity",   // guard ekstra: field kosong
        op: leaf.op,
        value: Array.isArray(leaf.value)
          ? leaf.value.join(",")
          : String(leaf.value ?? ""),
      };
    });
  });

  const addRow = () => {
    rowSeq += 1;
    setRows((r) => [...r, { id: rowSeq, field: "severity", op: "is",
      value: "" }]);
  };

  const update = (id: number, patch: Partial<RowState>) => {
    setRows((rs) => rs.map((r) => {
      if (r.id !== id) return r;
      const next = { ...r, ...patch };
      const def = fieldDef(next.field);
      if (def && !def.ops.includes(next.op)) next.op = def.ops[0];
      return next;
    }));
  };

  const apply = () => {
    const leaves = rows.map(rowToLeaf).filter(Boolean) as FilterLeaf[];
    if (!leaves.length) {
      onApply(null);
      onOpenChange(false);
      return;
    }
    if (leaves.length === 1) {
      onApply(leaves[0]);
    } else {
      onApply(glue === "and" ? { and: leaves } : { or: leaves });
    }
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl bg-zinc-950 border-zinc-800
                               max-h-[85vh] overflow-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-zinc-100">
            <Wand2 className="h-4 w-4 text-sky-400" />
            Filter Kustom (req 5) - AST aman, tanpa string query
          </DialogTitle>
        </DialogHeader>

        <div className="flex items-center gap-2 text-xs text-zinc-400">
          <span>Gabungkan baris dengan</span>
          <Button size="sm" variant={glue === "and" ? "secondary" : "ghost"}
                  onClick={() => setGlue("and")}>
            <ListTree className="h-3.5 w-3.5" /> AND (semua)
          </Button>
          <Button size="sm" variant={glue === "or" ? "secondary" : "ghost"}
                  onClick={() => setGlue("or")}>
            OR (salah satu)
          </Button>
        </div>

        <div className="space-y-2">
          {rows.map((r) => {
            const def = fieldDef(r.field);
            return (
              <div key={r.id} className="flex gap-2 items-start">
                <select
                  className="bg-zinc-900 border border-zinc-700 rounded-md
                             text-xs px-2 py-2 text-zinc-300 w-52"
                  value={r.field}
                  onChange={(e) => update(r.id, { field: e.target.value })}>
                  {FIELDS.map((f) => (
                    <option key={f.field} value={f.field}>{f.label}</option>
                  ))}
                </select>
                <select
                  className="bg-zinc-900 border border-zinc-700 rounded-md
                             text-xs px-2 py-2 text-zinc-300 w-44"
                  value={r.op}
                  onChange={(e) => update(r.id,
                    { op: e.target.value as FilterOp })}>
                  {(def?.ops ?? []).map((o) => (
                    <option key={o} value={o}>{OP_LABEL[o]}</option>
                  ))}
                </select>
                {def?.type === "list" && r.op === "is_one" ? (
                  <select
                    className="bg-zinc-900 border border-zinc-700 rounded-md
                               text-xs px-2 py-2 text-zinc-300 flex-1"
                    value={r.value.split(",")[0]}
                    onChange={(e) => update(r.id, { value: e.target.value })}>
                    <option value="">- pilih -</option>
                    {(r.field === "severity" ? SEV_OPTIONS
                      : r.field === "status" ? STATUS_OPTIONS
                      : r.field === "attack_status" ? ATTACK_STATUS_OPTIONS
                      : ENGINE_OPTIONS).map((o) => (
                      <option key={o} value={o}>{o}</option>
                    ))}
                  </select>
                ) : (
                  <Input
                    className="bg-zinc-900 border-zinc-700 text-xs flex-1"
                    placeholder={
                      r.op === "cidr" ? "10.0.0.0/8"
                      : r.op === "is_one" ? "nilai1, nilai2"
                      : r.op === "exclude" ? "nilai (atau nilai1,nilai2)"
                      : "nilai..."
                    }
                    value={r.value}
                    onChange={(e) => update(r.id, { value: e.target.value })} />
                )}
                <Button size="icon" variant="ghost"
                        className="text-zinc-500 hover:text-rose-400"
                        onClick={() => setRows((rs) =>
                          rs.filter((x) => x.id !== r.id))}>
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            );
          })}
          <Button size="sm" variant="outline" onClick={addRow}
                  className="border-zinc-700 text-zinc-300">
            <Plus className="h-3.5 w-3.5 mr-1" /> Tambah syarat
          </Button>
        </div>

        <p className="text-[11px] text-zinc-500">
          Field di luar whitelist ditolak API (400). Nilai include =
          wildcard case-insensitive. CIDR hanya untuk field IP.
        </p>
        <DialogFooter className="gap-2">
          <Button variant="ghost"
                  onClick={() => { onApply(null); onOpenChange(false); }}>
            Bersihkan filter
          </Button>
          <Button onClick={apply}
                  className="bg-sky-600 hover:bg-sky-500 text-white">
            Terapkan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Ringkasan AST utk badge (human-readable singkat) - null-safe (P0-3). */
export function filterSummary(ast: FilterAst | null): string {
  const safe = sanitizeFilterAst(ast);
  if (!safe) return "";
  const leafTextOf = (l: FilterLeaf | FilterGroup): string => {
    if (!l || !("field" in l)) return filterSummary(l as FilterAst);
    const def = fieldDef(l.field);
    const v = Array.isArray(l.value) ? l.value.join(" | ") : l.value;
    return `${def?.label ?? l.field} ${l.op} ${v}`;
  };
  if ("field" in safe) return leafTextOf(safe);
  const parts: string[] = [];
  if (safe.and) parts.push(safe.and.map(leafTextOf).join(" AND "));
  if (safe.or) parts.push(safe.or.map(leafTextOf).join(" OR "));
  if (safe.not) parts.push(`NOT ${filterSummary(safe.not as FilterAst)}`);
  return parts.join(" ");
}
