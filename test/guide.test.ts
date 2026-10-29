// Every approval screen and result sentence explains itself in plain words; technical text may
// appear only folded under "Exact details" (instruction.orient-the-person, card C6a-1).

import { test } from "node:test";
import assert from "node:assert/strict";
import { JOBS, type Guide } from "../src/jobs.ts";
import { approvePage } from "../src/page.ts";
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
      if (result?.ok === false && "vault" in JOBS[job]) assert.match(said, /nothing was handed over or accepted/);
      if (result === undefined && "vault" in JOBS[job]) assert.match(said, /^Not done/);
      assert.doesNotMatch(said.replace(/\[[^\]]*\]$/, ""), /[{}]|"\w+":/, `${job}: raw data in the result sentence`);
    }
  }
  assert.match(JOBS["gh.app.baseline"].done(ok), /23 repositories, 2 people, 3 apps, 1 deploy key/);
});

test("the GitHub list reads as grouped plain lines, marking new and gone, and says who may skip a branch rule", () => {
  const groups = plainChanges(CHANGES);
  const by = Object.fromEntries(groups.map((g) => [g.heading, g.items]));
  assert.deepEqual(by["Repositories: 2 new"], ["New: Shelflip (private)", "New: front-desk (public)"]);
  assert.deepEqual(by["Installed apps: 2 new"], [
    "New: wws-front-desk, on all repositories: can change: administration, contents; can read: metadata",
    "New: someone-else, on selected repositories: can change: contents",
  ]);
  assert.deepEqual(by["Deploy keys (a machine's key to one repo): 1 new, 1 gone"], ["New: a key on factory-core", "Gone: a key on sway"]);
  assert.deepEqual(by["Branch protection rules: 1 new"], [
    "New: front-desk, the main branch (on): the main branch can't be deleted; its history can't be rewritten (no force-push); changes need a pull request approved by 1 person, after the last change; who may skip it: not visible to the read-only watcher",
  ]);
  // A rule switched off reads as OFF, never as on.
  const off = plainChanges([`rulesets -front-desk:666:disabled:${RULESET}`])[0]!;
  assert.match(off.items[0]!, /^Gone: front-desk, the main branch \(OFF\)/);
});

test("the exact lines stay available, folded under Exact details", () => {
  const html = approvePage(grant("gh.app.baseline"), {}, "n");
  const folded = /<details>([\s\S]*?)<\/details>/.exec(html)![1]!;
  assert.ok(folded.includes("apps +wws-front-desk#111:all:administration=write"));
});
