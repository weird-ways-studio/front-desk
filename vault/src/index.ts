// The vault Worker. Two ways in, both declared in vault/wrangler.jsonc:
// - RPC from the front desk's service binding VAULT (methods on the default export below);
// - its own workers.dev address, behind the account-wide Cloudflare Access login, which serves
//   only the one-time setup page (setup.ts) and answers 404 once a key is stored.
// It loads no libraries -- only the runtime (cloudflare:workers, WebCrypto, fetch) and the files
// beside it. Rules: vault.ts.

import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { emailOf, handleSetup } from "./setup.ts";
import { VaultLogic } from "./vault.ts";
import { APPROVAL_API_VERSION } from "./approval.ts";
import { RUN_API_VERSION, RunBook, type OpRequest } from "./runs.ts";
import { CARD_API_VERSION, CARD_CAP, CardBook, JOBS_VERSION } from "./cards.ts";
import { PASSKEY_PIN } from "./passkey.ts";

interface Env {
  BOX: DurableObjectNamespace<VaultBox>;
}

/** One Durable Object holds the sealed master key, so setup and jobs run one at a time. */
export class VaultBox extends DurableObject<Env> {
  private logic() {
    return new VaultLogic(this.ctx.storage, (input, init) => fetch(input, init));
  }
  status() {
    return this.logic().status();
  }
  // The caller's email is worked out by the Worker from ctx.access and passed in (never a header).
  page(request: Request, email: string) {
    return handleSetup(request, this.logic(), email);
  }
  // Old-shape calls keep their extra arguments, so the vault can refuse them as wrong_shape (approval.ts).
  run(req: unknown, ...rest: unknown[]) {
    return this.logic().run(req, ...rest);
  }
  headcount(select?: unknown) {
    return this.logic().headcount(select);
  }
  ghReachNight() {
    return this.logic().ghReachNight();
  }
  ghReachStep(purpose?: unknown) {
    return this.logic().ghReachStep(purpose);
  }
  ghReachPreview() {
    return this.logic().ghReachPreview();
  }
  ghReachResults() {
    return this.logic().ghReachResults();
  }
  ghReachAck(id: unknown) {
    return this.logic().ghReachAck(id);
  }
  ghPreview() {
    return this.logic().ghPreview();
  }
  cfPreview() {
    return this.logic().cfPreview();
  }
  // Runs (card ae6147e4 4a-2a; rules in runs.ts). No desk route calls these until 4a-2b, and no run can be
  // opened until 4a-3, so in production every op refuses unknown_run.
  private runs() {
    return new RunBook(this.ctx.storage, (input, init) => fetch(input, init));
  }
  runOp(req: OpRequest) {
    return this.runs().op(req);
  }
  runEnd(id: string, how: "stopped" | "finished") {
    return this.runs().endRun(id, how);
  }
  runStatus(id: string) {
    return this.runs().status(id);
  }
  setKeyRev(rev: number) {
    return this.runs().setKeyRev(rev);
  }
  // Cards (card 85818ab1; rules in cards.ts). Each entry's read goes through VaultLogic.runCardEntry: today's tap path.
  private cards() {
    const logic = this.logic();
    return new CardBook(this.ctx.storage, (job, params, prf) => logic.runCardEntry(job, params, prf), PASSKEY_PIN);
  }
  cardOpen(req: unknown, ...rest: unknown[]) {
    return this.cards().open(req, ...rest);
  }
  cardRun(req: unknown, ...rest: unknown[]) {
    return this.cards().run(req, ...rest);
  }
  cardStop(card: string) {
    return this.cards().stop(card);
  }
  cardStatus(card: string) {
    return this.cards().status(card);
  }
  cardAck(card: string, index: number) {
    return this.cards().ack(card, index);
  }
  // gh.repo.create (card 77ec1e64): the durable record of a repo an entry made, and the recorder's receipt for its
  // done result, after which the vault adds it to the nightly list (cards.ts repoRecorded).
  repoFacts(grant: string) {
    return this.cards().repoFacts(grant);
  }
  repoRecorded(grant: unknown, body: unknown, receipt: unknown, ...rest: unknown[]) {
    return this.cards().repoRecorded(grant, body, receipt, ...rest);
  }
  // Called by the Cloudflare runtime when the time set by storage.setAlarm arrives (cards.ts armBy/rearm), never by
  // a request: closes cards left open past their deadline, drops held answers, prunes old books.
  async alarm() {
    await this.cards().alarm();
  }
}

/** What the front desk calls (types: vault/src/api.ts), plus the setup page. */
export default class Vault extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    return this.box().page(request, await emailOf(this.ctx.access));
  }
  private box() {
    return this.env.BOX.get(this.env.BOX.idFromName("vault"));
  }
  status() {
    return this.box().status();
  }
  run(req: unknown, ...rest: unknown[]) {
    return this.box().run(req, ...rest);
  }
  // The desk asks this before run(); a desk and vault on different versions refuse as wrong_shape (card bb86abf0).
  approvalApi() {
    return { version: APPROVAL_API_VERSION };
  }
  // The nightly count, called by the front desk's cron (../../src/index.ts scheduled). No tap; reads only.
  // `select` "any": an on-demand count folds in the newest complete reach read instead of the night's (card N2 5fdbf2ce).
  headcount(select?: unknown) {
    return this.box().headcount(select);
  }
  // The reach read (card N2 5fdbf2ce; rules in vault.ts). ghReachNight: the nightly cron's start-or-continue.
  // ghReachStep: one slice of the open generation, or ("demand") a new on-demand read. Both return only progress.
  ghReachNight() {
    return this.box().ghReachNight();
  }
  ghReachStep(purpose?: unknown) {
    return this.box().ghReachStep(purpose);
  }
  // What job gh.reach.baseline would accept, for Ben's approval screen (called at /request). Reads storage only.
  ghReachPreview() {
    return this.box().ghReachPreview();
  }
  // Final states and probe-key alarms the desk has not delivered yet; the desk acknowledges each after it pushed it.
  ghReachResults() {
    return this.box().ghReachResults();
  }
  ghReachAck(id: unknown) {
    return this.box().ghReachAck(id);
  }
  // What job gh.app.baseline would accept, for Ben's approval screen (called at /request). Reads only.
  ghPreview() {
    return this.box().ghPreview();
  }
  // What job cf.token.accept would accept, for Ben's approval screen (called at /request). Reads only.
  cfPreview() {
    return this.box().cfPreview();
  }
  // Runs (4a-2a). The desk checks runApi() first and refuses `vault_not_ready` on a vault without it (D9).
  runApi() {
    return { version: RUN_API_VERSION };
  }
  runOp(req: OpRequest) {
    return this.box().runOp(req);
  }
  runEnd(id: string, how: "stopped" | "finished") {
    return this.box().runEnd(id, how);
  }
  runStatus(id: string) {
    return this.box().runStatus(id);
  }
  // Called by the desk whenever the c-box key is removed or replaced, before it acknowledges the change (D3).
  setKeyRev(rev: number) {
    return this.box().setKeyRev(rev);
  }
  // Cards (card 85818ab1). The desk checks cardApi() first: another version, or a vault without cards, sends nothing.
  cardApi() {
    return { version: CARD_API_VERSION, jobs_version: JOBS_VERSION, cap: CARD_CAP };
  }
  cardOpen(req: unknown, ...rest: unknown[]) {
    return this.box().cardOpen(req, ...rest);
  }
  cardRun(req: unknown, ...rest: unknown[]) {
    return this.box().cardRun(req, ...rest);
  }
  cardStop(card: string) {
    return this.box().cardStop(card);
  }
  cardStatus(card: string) {
    return this.box().cardStatus(card);
  }
  cardAck(card: string, index: number) {
    return this.box().cardAck(card, index);
  }
  repoFacts(grant: string) {
    return this.box().repoFacts(grant);
  }
  repoRecorded(grant: unknown, body: unknown, receipt: unknown, ...rest: unknown[]) {
    return this.box().repoRecorded(grant, body, receipt, ...rest);
  }
}
