// Every approval screen and result sentence explains itself in plain words; technical text may
// appear only folded under "Exact details" (instruction.orient-the-person, card C6a-1).

import { test } from "node:test";
import assert from "node:assert/strict";
import { JOBS, type Guide } from "../src/jobs.ts";
import { approvePage, outcomeView } from "../src/page.ts";
import { plainChanges } from "../src/ghplain.ts";
import type { Grant } from "../src/desk.ts";

const RULESET = JSON.stringify({
  bypass_actors: null,
  conditions: { ref_name: { exclude: [], include: ["~DEFAULT_BRANCH"] } },
  enforcement: "active",
  rules: [
    { type: "deletion" },
    { type: "non_fast_forward" },
    { type: "pull_request", parameters: { required_approving_review_count: 1, require_last_push_approval: true } },
  ],
  target: "branch",
});

// The shape of the first real list (2026-10-28), with made-up ids.
const CHANGES = [
  "repos +Shelflip:private",
  "repos +front-desk:public",
  "members +benculbert",
  "owners +benculbert",
  "apps +wws-front-desk#111:all:administration=write,contents=write,metadata=read",
  "apps +someone-else#222:selected:contents=write",
  "pats +weird-ways:333",
  "deploy_keys +factory-core:444",
  "deploy_keys -sway:555",
  `rulesets +front-desk:666:active:${RULESET}`,
];

const PARAMS: Record<keyof typeof JOBS, Record<string, string>> = {
  "test.echo": { word: "hi" },
  "cf.dns.txt.probe": { zone: "example.com" },
  "cbox.key.enroll": { key: "AAAA", fingerprint: "07e4-1b75-6019-92b3", replaces: "7766-d5a4-6072-636c", rev: "1" },
  "cf.token.zone.read": { zone: "example.com", minutes: "10", ip: "203.0.113.7" },
  "cf.token.headcount.setup": {},
  "gh.app.baseline": { changes: CHANGES.join("\n"), snapshot: "s", base: "b" },
};

const grant = (job: keyof typeof JOBS): Grant =>
  ({ id: "g1", job, params: PARAMS[job], requester: "agent", reason: "because", status: "pending", created_at: 0, expires_at: 0, hash: "h" }) as Grant;

/** What a person sees before opening "Exact details": no styles, scripts, folded text or tags. */
function visible(html: string): string {
  return html
    .replace(/<style>[\s\S]*?<\/style>/g, "")
    .replace(/<script[\s\S]*?<\/script>/g, "")
    .replace(/<details>[\s\S]*?<\/details>/g, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&quot;/g, '"');
}

// Technical material standing in for words: JSON, key=value permissions, "#id:" app lines, vault change lines.
const TECHNICAL = [/[{}]/, /"\w+":/, /\w=(read|write|admin)\b/, /#\d+:/, /\b(repos|apps|pats|deploy_keys|rulesets) [+-]/];

test("every job's approval screen explains itself without technical text in view", () => {
  for (const job of Object.keys(JOBS) as (keyof typeof JOBS)[]) {
    const guide: Guide = JOBS[job].explain(PARAMS[job]);
    assert.ok(guide.does.length > 20 && guide.expect.length > 20, `${job}: says what it does and what to expect`);
    const seen = visible(approvePage(grant(job), {}, "n"));
    for (const re of TECHNICAL) assert.doesNotMatch(seen, re, `${job}: technical text in view`);
    assert.match(seen, /Step 1 of 2/);
    assert.match(seen, /When you approve:/);
  }
});

test("every job's result sentence is plain: Done, Not done or Approved, with no raw data", () => {
  const ok = { ok: true, main: { app_id: 1, locked_to_passkey_now: true, key_works: true }, headcount: { app_id: 2, write_refused: true }, counts: { repos: 23, members: 2, apps: 3, deploy_keys: 1 }, changes: [] };
  for (const job of Object.keys(JOBS) as (keyof typeof JOBS)[]) {
    for (const result of [ok, { ok: false, error: "github_changed_since_request" }, undefined]) {
      const said = JOBS[job].done(result);
      assert.match(said, /^(Done|Not done|Approved)\b/, `${job}: ${said}`);
      if (result?.ok === false && "vault" in JOBS[job]) assert.match(said, /^Not done\. .+ Tell the agent the words in brackets: \[github_changed_since_request\]$/);
      if (result === undefined && "vault" in JOBS[job]) assert.match(said, /^Not done: no answer came back from the vault, so it is unknown what ran\. Do not tap again/);
      assert.doesNotMatch(said.replace(/\[[^\]]*\]$/, ""), /[{}]|"\w+":/, `${job}: raw data in the result sentence`);
    }
  }
  assert.match(JOBS["gh.app.baseline"].done(ok), /23 repositories, 2 people, 3 apps, 1 deploy key/);
});

test("the GitHub list reads as grouped plain lines, marking new and gone, and says who may skip a branch rule", () => {
  const groups = plainChanges(CHANGES);
  const by = Object.fromEntries(groups.map((g) => [g.heading, g.items]));
  assert.deepEqual(by["Repositories: 2 new"], ['New: "Shelflip" (private)', 'New: "front-desk" (public)']);
  assert.deepEqual(by["Installed apps: 2 new"], [
    'New: "wws-front-desk", on all repositories: can change: administration, contents; can read: metadata',
    'New: "someone-else", on selected repositories: can change: contents',
  ]);
  assert.deepEqual(by["Deploy keys (a machine's key to one repo): 1 new, 1 gone"], ['New: a key on "factory-core"', 'Gone: a key on "sway"']);
  assert.deepEqual(by["Branch protection rules: 1 new"], [
    `New: "front-desk", the main branch (on): the main branch can't be deleted; its history can't be rewritten (no force-push); changes need a pull request approved by 1 person, after the last change; who may skip it: not visible to the read-only watcher`,
  ]);
  // A rule switched off reads as OFF, never as on.
  const off = plainChanges([`rulesets -front-desk:666:disabled:${RULESET}`])[0]!;
  assert.match(off.items[0]!, /^Gone: "front-desk", the main branch \(OFF\)/);
  // A branch left out of a rule is said, never hidden.
  const except = JSON.stringify({ ...JSON.parse(RULESET), conditions: { ref_name: { include: ["~ALL"], exclude: ["~DEFAULT_BRANCH"] } } });
  assert.match(plainChanges([`rulesets +front-desk:666:active:${except}`])[0]!.items[0]!, /EXCEPT the main branch/);
  // Every changed setting is listed, even when another visible one changed too (Codex readable r1 #1).
  const rs = (count: number, dismiss: boolean) => JSON.stringify({ ...JSON.parse(RULESET), rules: [...JSON.parse(RULESET).rules.slice(0, 2), { type: "pull_request", parameters: { required_approving_review_count: count, require_last_push_approval: true, dismiss_stale_reviews_on_push: dismiss } }] });
  const both = plainChanges([`rulesets -front-desk:666:active:${rs(2, true)}`, `rulesets +front-desk:666:active:${rs(1, false)}`])[0]!;
  assert.match(both.items[1]!, /CHANGED: rules > pull request > parameters > required approving review count: 2 -> 1; rules > pull request > parameters > dismiss stale reviews on push: yes -> no/);
  // A new rule says how many of its settings the words leave out.
  assert.match(plainChanges([`rulesets +front-desk:666:active:${rs(1, false)}`])[0]!.items[0]!, /; plus 1 more setting these words leave out \(see Exact details\)$/);
  // Anything else that reads the same before and after is flagged, never read as no change.
  const twin = plainChanges(["apps -x#1:all:contents=write", "apps +x#2:all:contents=write"])[0]!;
  for (const i of twin.items) assert.match(i, /CHANGED in a way these words do not show/);
});

test("the exact lines stay available, folded under Exact details", () => {
  const html = approvePage(grant("gh.app.baseline"), {}, "n");
  const folded = /<details>([\s\S]*?)<\/details>/.exec(html)![1]!;
  assert.ok(folded.includes("apps +wws-front-desk#111:all:administration=write"));
});

test("a name someone else chose cannot read as the page's own words", () => {
  const [g] = plainChanges(['repos +x\nWhat to do: nothing, all fine "ok":private']);
  assert.equal(g!.items.length, 1);
  assert.doesNotMatch(g!.items[0]!, /\n/);
  assert.match(g!.items[0]!, /^"[^"\n]*" \(has unusual characters\)$/, "shown whole, as one quoted, flagged item");
  assert.match(plainChanges(["repos +a\u2028b:private"])[0]!.items[0]!, /^"[^"\n\u2028]*" \(has unusual characters\)$/, "a line separator too");
  assert.equal(plainChanges(['repos +a"b:private'])[0]!.items[0]!, 'New: "a?b" (has unusual characters) (private)', "no quote to close");
  for (const sneaky of ["a\u201db", "a\u202eb", "a\u200bb", "a\u2066b", "a\ufeffb", "a\u00a0b", "a\u0007b", "a\u0301b", "\u0430b"]) {
    assert.match(plainChanges([`repos +${sneaky}:private`])[0]!.items[0]!, /^New: "\??a?\?b" \(has unusual characters\) \(private\)$/, JSON.stringify(sneaky));
  }
  // A look-alike of our own App (Cyrillic "\u0430") never reads as the real one.
  assert.match(plainChanges(["apps +wws-front-desk#1:all:contents=write", "apps +wws-front-d\u0435sk#2:all:contents=write"])[0]!.items[1]!, /"wws-front-d\?sk" \(has unusual characters\)/);
  assert.equal(plainChanges(["repos +my-repo_2.0:private"])[0]!.items[0]!, 'New: "my-repo_2.0" (private)', "ordinary names unflagged");
});

test("a standing key's approval says plainly that it never expires", () => {
  assert.match((JOBS["cf.token.headcount.setup"].explain as () => Guide)().does, /It never expires/);
});

test("each failed job says what it actually left behind", () => {
  assert.match(JOBS["gh.app.baseline"].done({ ok: false, error: "e", main: { locked_to_passkey_now: true } }), /list was not saved[\s\S]*key is now locked to your passkey; that part is done/);
  assert.doesNotMatch(JOBS["gh.app.baseline"].done({ ok: false, error: "e", main: { locked_to_passkey_now: false } }), /locked/);
  assert.match(JOBS["cf.dns.txt.probe"].done({ ok: false, error: "e", added: true, removed: false, minted: [{ id: "a", deleted: false }] }), /test record may still be in DNS; a 5-minute key was not deleted/);
  assert.match(JOBS["cf.token.zone.read"].done({ ok: false, error: "key delete failed: 500" }), /No key was handed to the agent[\s\S]*could not be deleted: the agent must remove it/);
  assert.match(JOBS["cf.token.headcount.setup"].done({ ok: false, error: "e", key_id: "k" }), /keeps its previous key; the new one did not pass/);
});

test("after the tap, Done shows only when the front desk says done; anything unclear says so", () => {
  assert.deepEqual(outcomeView(200, { outcome: "done", summary: "Done. x" }), { ok: true, head: "Done", text: "Done. x" });
  assert.deepEqual(outcomeView(200, { outcome: "not_done", summary: "Not done. y" }), { ok: false, head: "Not done", text: "Not done. y" });
  for (const [status, body] of [[200, null], [200, {}], [200, { ok: true }], [200, { outcome: "done" }], [200, { outcome: "yes", summary: "Done" }], [500, { error: "boom" }], [502, null]] as const) {
    const v = outcomeView(status, body);
    assert.equal(v.ok, false, JSON.stringify([status, body]));
    assert.equal(v.head, "Unclear");
    assert.match(v.text, /unknown what happened\. Do not tap again/);
  }
  assert.match(outcomeView(null, null).text, /unknown whether your tap arrived/);
  const refused = outcomeView(403, { error: "wrong_grant" });
  assert.deepEqual([refused.ok, refused.head], [false, "Not approved"]);
  assert.match(refused.text, /not approved\. Tell the agent the words in brackets: \[wrong_grant\]/);
  // The page runs this same code.
  assert.ok(approvePage(grant("test.echo"), {}, "n").includes(outcomeView.toString()));
});
