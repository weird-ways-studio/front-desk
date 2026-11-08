// Cards, desk side (card 85818ab1; studio-os docs/specifications/studio-architecture/spike-08313e62/REFINE-85818ab1.md
// v2.2, Outcome 1 and 7, U4-U6, V1-V4, W1). An agent sends 1-2 named jobs in one signed POST /card; Ben reads one page
// and taps Face ID once; the desk then, per entry in order: records the approval with the Observatory (getting its
// signed receipt), asks the vault to run that entry (`cardRun`: the vault checks the receipt, the order, the deadline,
// and that Ben signed this card), and stops at the first entry that is not `done`. The vault's card book
// (vault/src/cards.ts) is the boundary; the desk only drives it and shows it.
//
// `finish()` is the one recovery step: any read of a card (Ben's page, Stop, the agent's GET /card/<id>) reads the
// vault's book, stores each answer the vault still holds, tells the vault it may delete its copy (`cardAck`), and
// records each missing result from the vault's state with frozen bytes, so a crash anywhere is finished by the next read.
// If nobody reads, the Observatory's checker raises `card-incomplete` an hour after the deadline (586da182).

import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { APPROVE_WINDOW_MS, CHALLENGE_TTL_MS, COLLECT_WINDOW_MS, Desk, DeskError, PRF_MASTER_LABEL, assertionOf, challengeCarries, grantHash, hexToBytes, prfOf, saltFor, withoutSecret, type Grant, type Source } from "./desk.ts";
import { CARD_ELIGIBLE, JOBS, type Job, type JobName } from "./jobs.ts";
import { keyRev } from "./cboxkey.ts";
import type { Receipt } from "./recorder.ts";
import type { CardView, EntryState, VaultCardApi } from "../vault/src/api.ts";
import { CARD_API_VERSION } from "../vault/src/cards.ts";
import { CARD_RUN_MS, cardHashOf, type Manifest } from "../vault/src/cardcopy.ts";

/** The desk's record of a card (storage key `card:<id>`). Its grants are ordinary `grant:<id>` records carrying `card`. */
export interface DeskCard {
  id: string;
  requester: string;
  manifest: Manifest;
  hash: string; // the card hash Ben's tap signs
  grants: string[]; // grant ids, in run order
  // "stopped" before the tap: never sent to Ben (partial freeze, V4), Stopped by Ben, or not opened in the vault.
  status: "pending" | "approved" | "stopped";
  created_at: number;
  expires_at: number; // every entry's expiry: Ben's tap must land before it
  cbox_rev: number; // the c-box key generation the card was asked under; the vault refuses any change (T10)
  approved_at?: number;
  stopped?: string;
}

export interface CardEntryReport {
  index: number;
  grant: string;
  job: string;
  does: string; // the plain line Ben read
  state: EntryState;
  at?: number;
  late?: string;
  answer?: unknown;
  answer_erased?: true; // held only until the card closed COLLECT_WINDOW_MS ago (V3)
  receipts: Partial<Record<string, Omit<Receipt, "body">>>;
}
export interface CardReport {
  card: string;
  status: DeskCard["status"];
  requester: string;
  expires_at: number;
  deadline: number;
  stopped?: string;
  closed_at?: number;
  entries: CardEntryReport[];
}

const terminal = (s: EntryState) => s !== "waiting" && s !== "dispatching";
const strip = ({ body: _b, ...r }: Receipt): Omit<Receipt, "body"> => r;
const codeOf = (e: unknown) => (e instanceof Error && typeof e.message === "string" && e.message ? e.message : "unknown error").slice(0, 120);

/** The result outcome for a vault entry state, or undefined while it may still change. */
export function outcomeOf(state: EntryState, pastDeadline: boolean): "done" | "failed" | "unknown" | undefined {
  if (state === "done") return "done";
  if (state === "failed" || state === "not_run") return "failed";
  if (state === "unknown" || (state === "dispatching" && pastDeadline)) return "unknown";
  return undefined;
}

export class CardDesk extends Desk {
  private cards(): VaultCardApi {
    const v = this.hooks.vault;
    if (!v?.cardApi || !v.cardOpen || !v.cardRun || !v.cardStop || !v.cardStatus || !v.cardAck) throw new DeskError("vault_unavailable", 502);
    return v as VaultCardApi;
  }

  // A vault on another card version would misread every call: nothing is sent to it (as approvalApi, bb86abf0 R6).
  private async cardApi() {
    const a = await Promise.resolve().then(() => this.cards().cardApi()).catch(() => null);
    if (a?.version !== CARD_API_VERSION || !Number.isSafeInteger(a.cap) || !Number.isSafeInteger(a.jobs_version)) throw new DeskError("vault_unavailable", 502);
    return a;
  }

  async card(id: string): Promise<DeskCard> {
    const c = await this.store.get<DeskCard>(`card:${id}`);
    if (!c) throw new DeskError("no_such_card", 404);
    return c;
  }

  /**
   * POST /card. Validates every entry, records each entry's request (carrying `card`) and verdict, and only then
   * makes the card visible. Any recording failure freezes the card: every grant `stopped`, no link (V4).
   */
  async requestCard(input: unknown, requester: string, now: number, source: Source = {}): Promise<{ card: DeskCard; grants: Grant[] }> {
    await this.eraseStaleSecrets(now);
    await this.requireSigned(source, requester, "card", now);
    const refuse = async (code: string, status = 400) => {
      await this.log({ event: "refused", requester, detail: `card: ${code}` }, now);
      return new DeskError(code, status);
    };
    const body = input as { entries?: unknown } | null;
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).join() !== "entries" || !Array.isArray(body.entries) || !body.entries.length) throw await refuse("bad_card");
    const api = await this.cardApi().catch(async (e) => {
      throw await refuse((e as DeskError).code, 502);
    });
    if (body.entries.length > api.cap) throw await refuse("too_many_entries");
    const asked: { job: JobName; params: Record<string, string>; reason: string }[] = [];
    for (const raw of body.entries as unknown[]) {
      const e = (raw ?? {}) as { job?: unknown; params?: unknown; reason?: unknown };
      if (typeof e.job !== "string" || !Object.hasOwn(JOBS, e.job) || !CARD_ELIGIBLE.includes(e.job as JobName)) throw await refuse("job_not_on_cards");
      const params = (JOBS[e.job as JobName] as Job).validate(e.params);
      if (!params) throw await refuse("bad_params");
      if (typeof e.reason !== "string" || !e.reason.trim() || e.reason.length > 200) throw await refuse("bad_reason");
      asked.push({ job: e.job as JobName, params, reason: e.reason.trim() });
    }
    // One card waiting for Ben per requester. A card frozen as "not sent" counts until its grants expire (V4).
    const waiting = [...(await this.store.list<DeskCard>({ prefix: "card:" })).values()].filter((c) => c.requester === requester && c.expires_at > now && c.approved_at === undefined && c.stopped !== "stopped by Ben");
    if (waiting.length) throw await refuse("too_many_pending", 429);
    const id = crypto.randomUUID();
    const expires_at = now + APPROVE_WINDOW_MS;
    const cbox_rev = await keyRev(this.store);
    const grants: Grant[] = [];
    for (const a of asked) {
      const base = { id: crypto.randomUUID(), job: a.job, params: a.params, requester, expires_at };
      grants.push({ ...base, reason: a.reason, created_at: now, hash: await grantHash(base), status: "pending", card: id, cbox_rev });
    }
    const manifest: Manifest = { kind: "card/v1", card: id, requester, entries: grants.map((g) => g.hash), deadline: expires_at + CARD_RUN_MS, jobs_version: api.jobs_version };
    // Stored frozen first: it becomes "pending" (shown to Ben) only after every record is in.
    const card: DeskCard = { id, requester, manifest, hash: await cardHashOf(manifest), grants: grants.map((g) => g.id), status: "stopped", stopped: "card not sent", created_at: now, expires_at, cbox_rev };
    await this.store.put(`card:${id}`, card);
    for (const g of grants) {
      try {
        const rq = await this.record(g, "request", { params: g.params, requester, reason: g.reason, created_at: now, expires_at, grant_hash: g.hash, card: id }, now);
        g.recorded = { request: rq.sha256 };
        g.receipts = { request: strip(rq) };
        const vd = await this.record(g, "verdict", { overseer: "not_checked" }, now);
        g.recorded.verdict = vd.seq;
        g.receipts.verdict = strip(vd);
        await this.store.put(`grant:${g.id}`, g);
      } catch {
        // Partial freeze: grants already stored, and this one, can never be approved (not pending, and on a card).
        for (const x of grants) await this.store.put(`grant:${x.id}`, { ...x, status: "stopped" });
        await this.log({ event: "card_not_sent", requester, detail: `card ${id}: a record was not taken; nothing sent to Ben` }, now);
        throw new DeskError("card_not_sent", 503);
      }
    }
    const sent: DeskCard = { ...card, status: "pending", stopped: undefined };
    await this.store.put(`card:${id}`, sent);
    await this.log({ event: "card_requested", requester, expires_at, detail: `card ${id}: ${grants.map((g, i) => `${i + 1}. ${g.job}`).join(" ")}` }, now);
    return { card: sent, grants };
  }

  /** The tap's challenge: 16 random bytes + the card hash, so the answer can only ever approve this card. */
  async cardOptions(id: string, now: number) {
    const c = await this.card(id);
    if (c.status !== "pending") throw new DeskError("not_pending", 409);
    if (now > c.expires_at) throw new DeskError("card_expired", 410);
    const keys = await this.passkeys();
    if (!keys.length) throw new DeskError("no_passkey_enrolled", 409);
    const challenge = new Uint8Array([...crypto.getRandomValues(new Uint8Array(16)), ...hexToBytes(c.hash)]);
    const options = await generateAuthenticationOptions({ rpID: this.site.rpID, challenge, userVerification: "required", allowCredentials: keys.map((k) => ({ id: k.id })) });
    await this.store.put(`challenge:${options.challenge}`, { purpose: "card", grant_id: c.id, expires_at: now + CHALLENGE_TTL_MS, used: false });
    return { ...options, prfSalt: await saltFor(PRF_MASTER_LABEL) };
  }

  /** Ben's one tap: checks it, opens the card in the vault, runs each entry in order, stops at the first not done. */
  async approveCard(id: string, response: AuthenticationResponseJSON, now: number): Promise<CardReport> {
    const refuse = async (code: string, status: number) => {
      await this.log({ event: "refused", detail: `card ${id}: ${code}` }, now);
      return new DeskError(code, status);
    };
    const first = await this.card(id);
    if (first.status !== "pending") throw await refuse("not_pending", 409);
    if (now > first.expires_at) throw await refuse("card_expired", 410);
    const { challenge, record } = await this.takeChallenge(response, "card", now);
    if (record.grant_id !== id || !challengeCarries(challenge, first.hash)) throw await refuse("wrong_card", 403);
    const fail = (detail: string) => this.log({ event: "refused", detail: `card ${id}: ${detail}` }, now);
    const { key, newCounter } = await this.verifyPasskey(response, challenge, fail);
    const prf = prfOf(response);
    if (!prf) {
      await fail("no passkey secret sent");
      throw new DeskError("prf_missing", 422);
    }
    // Re-read after the crypto: another request may have run meanwhile (Release Checklist 6.2).
    const c = await this.card(id);
    if (c.status !== "pending") throw await refuse("not_pending", 409);
    if (c.cbox_rev !== (await keyRev(this.store))) throw await refuse("cbox_key_changed", 409);
    const grants = await Promise.all(c.grants.map((g) => this.grant(g)));
    if (grants.some((g) => g.status !== "pending" || !g.recorded?.request || g.recorded.verdict === undefined)) throw await refuse("not_recorded", 409);
    await this.commitCounter(key.id, newCounter);
    // Committed before anything is sent, so a replay of this tap finds the card not pending.
    await this.store.put(`card:${id}`, { ...c, status: "approved", approved_at: now });
    for (const g of grants) await this.store.put(`grant:${g.id}`, { ...g, status: "approved", approved_at: now });
    await this.log({ event: "card_approved", requester: c.requester, detail: `card ${id}: ${grants.length} entries` }, now);
    const assertion = assertionOf(response);
    try {
      await this.cardApi();
      const fields = grants.map((g) => ({ id: g.id, job: g.job, params: g.params, requester: g.requester, expires_at: g.expires_at }));
      await this.cards().cardOpen({ manifest: c.manifest, grants: fields, assertion, key_rev: c.cbox_rev });
    } catch (e) {
      // A refusal, or no clear answer: the vault's book is the truth (U5 class 3). No book: this tap started nothing.
      const opened = await Promise.resolve().then(() => this.cards().cardStatus(id)).then(() => true, () => false);
      if (!opened) {
        const latest = await this.card(id);
        await this.store.put(`card:${id}`, { ...latest, status: "stopped", stopped: `not opened: ${codeOf(e)}` });
        for (const g of grants) await this.store.put(`grant:${g.id}`, { ...(await this.grant(g.id)), status: "stopped" });
        await this.log({ event: "stopped", detail: `card ${id}: the vault did not open it; this tap started nothing [${codeOf(e)}]` }, now);
        return this.finish(id, now);
      }
    }
    for (const [i, g] of grants.entries()) {
      if (await this.runEntry(c, g, i, assertion, prf, now)) continue;
      // Nothing after a failure, a refusal or an unclear answer starts (idempotent if the vault already stopped it).
      await Promise.resolve().then(() => this.cards().cardStop(id)).catch(() => undefined);
      break;
    }
    return this.finish(id, now);
  }

  /** One entry: its approval recorded (signed receipt), then `cardRun`. True only when the vault says `done`. */
  private async runEntry(c: DeskCard, g: Grant, i: number, assertion: ReturnType<typeof assertionOf>, prf: string, now: number): Promise<boolean> {
    let rc: Receipt;
    try {
      rc = await this.record(g, "approval", { grant_hash: g.hash, approved_at: now, assertion, approval_kind: "card/v1", manifest: c.manifest }, now);
    } catch {
      await this.log({ event: "stopped", ...this.grantFacts(g), detail: `card entry ${i + 1}: approval not recorded; it and every later entry did not start` }, now);
      return false;
    }
    const latest = await this.grant(g.id);
    await this.store.put(`grant:${g.id}`, { ...latest, recorded: { ...latest.recorded!, approval: rc.seq }, receipts: { ...latest.receipts, approval: strip(rc) } });
    if (rc.sig === undefined || rc.body === undefined) {
      await this.log({ event: "stopped", ...this.grantFacts(g), detail: `card entry ${i + 1}: the recorder's receipt is not signed; not started` }, now);
      return false;
    }
    try {
      const receipt = { v: rc.v!, seq: rc.seq, key: rc.key!, grant: rc.grant, stage: rc.stage, sha256: rc.sha256, recorded_at: rc.recorded_at!, sig: rc.sig };
      const r = await this.cards().cardRun({ card: c.id, index: i, receipt, approval_body: rc.body, prf, key_rev: c.cbox_rev });
      await this.log({ event: r.state === "done" ? "job_done" : "job_failed", ...this.grantFacts(g), detail: `card entry ${i + 1}: ${r.state}` }, now);
      return r.state === "done";
    } catch (e) {
      await this.log({ event: "job_failed", ...this.grantFacts(g), detail: `card entry ${i + 1}: not started, or no answer [${codeOf(e)}]` }, now);
      return false;
    }
  }

  /** Ben's Stop: before the tap, the card is never run; after it, the vault starts nothing more (T5: one already out runs to its answer). */
  async stopCard(id: string, now: number): Promise<CardReport> {
    const c = await this.card(id);
    if (c.status === "pending") {
      await this.store.put(`card:${id}`, { ...c, status: "stopped", stopped: "stopped by Ben" });
      for (const g of c.grants) await this.store.put(`grant:${g}`, { ...(await this.grant(g)), status: "stopped" });
    } else if (c.status === "approved") {
      await Promise.resolve().then(() => this.cards().cardStop(id)).catch(() => undefined);
    }
    await this.log({ event: "card_stopped", requester: c.requester, detail: `card ${id}: stopped by Ben` }, now);
    return this.finish(id, now);
  }

  /** The agent's signed GET /card/<id>: every entry's state, held answers and receipts. */
  async collectCard(id: string, requester: string, now: number, source: Source = {}): Promise<CardReport> {
    await this.requireSigned(source, requester, "card", now);
    const c = await this.card(id);
    if (c.requester !== requester) throw new DeskError("not_your_card", 403);
    return this.finish(id, now);
  }

  /**
   * Idempotent recovery (U4, V1-V3, W1): from the vault's book, store answers still held (before acking them), and
   * record each missing result with bytes frozen in the grant before the first send. Past the collect window it
   * neither stores nor returns answers, and erases the desk's copies.
   */
  async finish(id: string, now: number): Promise<CardReport> {
    const c = await this.card(id);
    const v: CardView | undefined = c.status === "approved" || c.approved_at !== undefined ? await Promise.resolve().then(() => this.cards().cardStatus(id)).catch(() => undefined) : undefined;
    const open = !v || v.closed_at === undefined || now <= v.closed_at + COLLECT_WINDOW_MS;
    for (const [i, gid] of c.grants.entries()) {
      const e = v?.entries[i];
      if (v && e && e.grant === gid) {
        const held = Object.hasOwn(v.answers, i);
        let g = await this.grant(gid);
        if (open && held && terminal(e.state) && g.result === undefined && !g.answer_erased) {
          g = { ...(await this.grant(gid)), result: withoutSecret(v.answers[i]) };
          await this.store.put(`grant:${gid}`, g);
        }
        // Only after the desk's own write has completed may the vault drop its copy (V2).
        if (held && g.result !== undefined) await Promise.resolve().then(() => this.cards().cardAck(id, i)).catch(() => false);
        const outcome = outcomeOf(e.state, now > v.deadline);
        if (outcome && g.recorded?.approval !== undefined && g.recorded.result === undefined) {
          // The vault's times, never the caller's clock: settle time; close time; the stored deadline if still overdue (W1).
          const at = (e.state === "done" || e.state === "failed") && e.at !== undefined ? e.at : e.state === "dispatching" ? v.deadline : (v.closed_at ?? v.deadline);
          await this.sendResult(gid, outcome, at, now);
        }
      }
      if (!open) {
        const g = await this.grant(gid);
        if (g.result !== undefined) await this.store.put(`grant:${gid}`, { ...g, result: undefined, answer_erased: true });
      }
    }
    return this.report(await this.card(id), v, open);
  }

  // The result record, frozen: built once, stored in the grant (re-read, written only if absent), and every send
  // after that reuses the stored bytes, so the recorder answers the same receipt (V1).
  private async sendResult(gid: string, outcome: string, at: number, now: number): Promise<void> {
    let g = await this.grant(gid);
    if (g.result_body === undefined) {
      const body = JSON.stringify({ v: 1, grant: g.id, stage: "result", job: g.job, request: g.recorded!.request, outcome, at });
      g = await this.grant(gid);
      if (g.result_body === undefined) {
        g = { ...g, result_body: body };
        await this.store.put(`grant:${gid}`, g);
      }
    }
    try {
      const rc = await this.record(g, "result", {}, now, g.result_body);
      const latest = await this.grant(gid);
      await this.store.put(`grant:${gid}`, { ...latest, recorded: { ...latest.recorded!, result: rc.seq }, receipts: { ...latest.receipts, result: strip(rc) } });
    } catch {
      // record() already logged why. The next read resends the same bytes; the checker's card-incomplete is the backstop.
      await this.log({ event: "result_unrecorded", ...this.grantFacts(g) }, now);
    }
  }

  private async report(c: DeskCard, v: CardView | undefined, open: boolean): Promise<CardReport> {
    const entries: CardEntryReport[] = [];
    for (const [i, gid] of c.grants.entries()) {
      const g = await this.grant(gid);
      const e = v?.entries[i];
      entries.push({
        index: i,
        grant: gid,
        job: g.job,
        does: (JOBS[g.job] as Job).explain(g.params).does,
        state: e?.state ?? (c.status === "pending" ? "waiting" : "not_run"),
        ...(e?.at !== undefined ? { at: e.at } : {}),
        ...(e?.late !== undefined ? { late: e.late } : {}),
        ...(open && g.result !== undefined ? { answer: withoutSecret(g.result) } : {}),
        ...(g.answer_erased || (!open && g.result !== undefined) ? { answer_erased: true as const } : {}),
        receipts: g.receipts ?? {},
      });
    }
    return { card: c.id, status: c.status, requester: c.requester, expires_at: c.expires_at, deadline: c.manifest.deadline, ...((v?.stopped ?? c.stopped) ? { stopped: v?.stopped ?? c.stopped } : {}), ...(v?.closed_at !== undefined ? { closed_at: v.closed_at } : {}), entries };
  }
}
