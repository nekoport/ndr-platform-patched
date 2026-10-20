"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ShieldCheck, TriangleAlert } from "lucide-react";
import { useState } from "react";

export function LoginView({ onLogin, demo }: {
  onLogin: (username: string, password: string) => Promise<string | null>;
  demo: boolean;
}) {
  const [username, setUsername] = useState(demo ? "admin" : "");
  const [password, setPassword] = useState(demo ? "demo" : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const err = await onLogin(username, password);
    setBusy(false);
    if (err) setError(err);
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-4">
      <div className="w-full max-w-sm space-y-4">
        <div className="flex flex-col items-center gap-2 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-emerald-900 bg-emerald-950/50">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-100">NDR Console</h1>
          <p className="text-sm text-zinc-500">Network Detection &amp; Response - Phase 0-2</p>
        </div>

        <Card className="border-zinc-800 bg-zinc-900/70">
          <form onSubmit={submit}>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Sign in</CardTitle>
              <CardDescription>
                {demo
                  ? "Demo mode: any credentials are accepted."
                  : "Use your SOC account. Sessions are audited."}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {demo && (
                <div className="rounded-md border border-emerald-900 bg-emerald-950/40 px-3 py-2 text-xs leading-relaxed text-emerald-300">
                  <span className="font-semibold">Demo credentials:</span> username{" "}
                  <code className="rounded bg-zinc-900 px-1 font-mono">admin</code> / password{" "}
                  <code className="rounded bg-zinc-900 px-1 font-mono">demo</code>
                  <span className="mt-0.5 block text-[10px] text-emerald-400/70">
                    already pre-filled below - just click Sign in. No backend needed.
                  </span>
                </div>
              )}
              <div className="space-y-1.5">
                <Label htmlFor="username">Username</Label>
                <Input id="username" value={username} autoComplete="username"
                       onChange={(e) => setUsername(e.target.value)} required />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <Input id="password" type="password" value={password} autoComplete="current-password"
                       onChange={(e) => setPassword(e.target.value)} required />
              </div>
              {error && (
                <p className="flex items-center gap-1.5 rounded-md border border-red-900 bg-red-950/60 px-2.5 py-2 text-xs text-red-300">
                  <TriangleAlert className="h-3.5 w-3.5 shrink-0" /> {error}
                </p>
              )}
            </CardContent>
            <CardFooter>
              <Button type="submit" className="w-full bg-emerald-600 text-white hover:bg-emerald-500"
                      disabled={busy}>
                {busy ? "Signing in..." : "Sign in"}
              </Button>
            </CardFooter>
          </form>
        </Card>

        <p className="text-center text-[11px] leading-relaxed text-zinc-600">
          Failed logins are rate-limited and recorded in the audit log.
          {demo && <><br />Backend not connected - showing demo data.</>}
        </p>
      </div>
    </div>
  );
}
