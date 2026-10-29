// Plain words for the GitHub list Ben accepts (job gh.app.baseline). The vault speaks in compact
// lines like "apps +slug#id:all:administration=write"; Ben reads sections like "Installed apps: 1 new".
// The exact lines stay on the page, folded away under the plain version (instruction.orient-the-person).

import type { GhBaselineResult } from "../vault/src/api.ts";

const KINDS: Record<string, string> = {
  repos: "Repositories",
  members: "People in the organization",
  owners: "Owners (full control of the organization)",
  outside: "Outside collaborators (people let into single repos)",
  invites: "Pending invitations",
  apps: "Installed apps",
  pats: "Personal access tokens with access to the organization",
  deploy_keys: "Deploy keys (a machine's key to one repo)",
  rulesets: "Branch protection rules",
};

// Count words for the done sentence: [one, many].
const COUNTS: Record<string, [string, string]> = {
  repos: ["repository", "repositories"],
  members: ["person", "people"],
  owners: ["owner", "owners"],
  outside: ["outside collaborator", "outside collaborators"],
  invites: ["pending invitation", "pending invitations"],
  apps: ["app", "apps"],
  pats: ["personal access token", "personal access tokens"],
  deploy_keys: ["deploy key", "deploy keys"],
  rulesets: ["branch rule", "branch rules"],
};

/**
 * A name someone else chose (a key's name, a repo's) as inert text: plain ASCII, no quotes to close,
 * at most 60 characters, flagged when anything was replaced. It can never pass as the page's own words.
 */
export function name(raw: string): string {
  // Plain ASCII letters, digits, spaces and a few symbols only (GitHub's own names are all ASCII).
  // Anything else -- look-alike letters, accents stacked on letters, invisible or text-direction
  // characters, quotes, line breaks -- becomes "?" and the name is flagged, so a disguise stands out.
  const kept = raw.replace(/[^A-Za-z0-9 ._\-@/()+,:#]/g, "?");
  const flat = kept.replace(/\s+/g, " ").trim();
  const short = flat.length > 60 ? `${flat.slice(0, 57)}...` : flat;
  return `"${short}"${kept === raw ? "" : " (has unusual characters)"}`;
}

/** Any character outside printable ASCII becomes "?", so no text can hide, reorder or break a line. */
export const ascii = (t: string) => t.replace(/[^\x20-\x7e]/g, "?");

/** "administration=write,metadata=read" -> "can change: administration; can read: metadata". */
function perms(list: string): string {
  const by: Record<string, string[]> = { write: [], read: [], admin: [] };
  for (const p of list.split(",").filter(Boolean)) {
    const [name, level] = p.split("=");
    (by[level ?? ""] ?? (by[level ?? ""] = [])).push((name ?? "").replace(/_/g, " "));
  }
  const parts = [];
  if (by.admin!.length) parts.push(`full control of: ${by.admin!.join(", ")}`);
  if (by.write!.length) parts.push(`can change: ${by.write!.join(", ")}`);
  if (by.read!.length) parts.push(`can read: ${by.read!.join(", ")}`);
  for (const [level, names] of Object.entries(by)) if (!["admin", "write", "read"].includes(level) && names.length) parts.push(`${level}: ${names.join(", ")}`);
  return parts.join("; ") || "no permissions listed";
}

interface Ruleset {
  conditions?: { ref_name?: { include?: string[] } };
  rules?: { type: string; parameters?: { required_approving_review_count?: number; require_last_push_approval?: boolean } }[];
  bypass_actors?: unknown[] | null;
}

/** One ruleset in words: what it protects, each rule, and who may skip it. */
function ruleset(repo: string, enforcement: string, raw: string): string {
  let r: Ruleset;
  try {
    r = JSON.parse(raw) as Ruleset;
  } catch {
    return `${repo}: a rule the page cannot read (see the exact details below)`;
  }
  const include = r.conditions?.ref_name?.include ?? [];
  const exclude = (r.conditions?.ref_name as { exclude?: string[] } | undefined)?.exclude ?? [];
  const branch =
    (include.includes("~DEFAULT_BRANCH") ? "the main branch" : include.length ? `branches ${include.map(name).join(", ")}` : "some branches") +
    (exclude.length ? `, EXCEPT ${exclude.map((b) => (b === "~DEFAULT_BRANCH" ? "the main branch" : name(b))).join(", ")}` : "");
  const state = enforcement === "active" ? "on" : enforcement === "evaluate" ? "test mode only, not enforced" : "OFF";
  const rules = (r.rules ?? []).map((rule) => {
    if (rule.type === "deletion") return `${branch} can't be deleted`;
    if (rule.type === "non_fast_forward") return `its history can't be rewritten (no force-push)`;
    if (rule.type === "pull_request") {
      const n = rule.parameters?.required_approving_review_count ?? 0;
      return `changes need a pull request approved by ${n} ${n === 1 ? "person" : "people"}${rule.parameters?.require_last_push_approval ? ", after the last change" : ""}`;
    }
    if (rule.type === "required_status_checks") return "automatic checks must pass";
    if (rule.type === "required_signatures") return "changes must be signed";
    return `rule "${rule.type}"`;
  });
  const skip = r.bypass_actors == null ? "who may skip it: not visible to the read-only watcher" : r.bypass_actors.length ? `${r.bypass_actors.length} may skip it` : "nobody may skip it";
  return `${repo}, ${branch} (${state}): ${rules.join("; ") || "no rules"}; ${skip}`;
}

/** Every setting of a ruleset as "where: value", rules keyed by their type, so two versions compare. */
function settings(raw: string): Map<string, string> | null {
  let r: unknown;
  try {
    r = JSON.parse(raw);
  } catch {
    return null;
  }
  const out = new Map<string, string>();
  const walk = (v: unknown, at: string) => {
    if (Array.isArray(v) && at.endsWith("rules")) for (const rule of v as { type?: string }[]) walk(rule, `${at} > ${String(rule?.type ?? "?")}`);
    else if (v && typeof v === "object" && !Array.isArray(v)) for (const [k, x] of Object.entries(v)) walk(x, at ? `${at} > ${k}` : k);
    else out.set(at, v === true ? "yes" : v === false ? "no" : v === null ? "not visible" : JSON.stringify(v));
  };
  walk(r, "");
  return out;
}

/** What differs between two versions of a ruleset, setting by setting, in words. */
function settingChanges(before: string, after: string): string[] {
  const a = settings(before), b = settings(after);
  if (!a || !b) return ["a setting the page cannot read"];
  const keys = [...new Set([...a.keys(), ...b.keys()])].filter((k) => a.get(k) !== b.get(k));
  return keys.map((k) => `${k.replace(/_/g, " ")}: ${a.get(k) ?? "not set"} -> ${b.get(k) ?? "not set"}`);
}

/** How many of a ruleset's settings the plain sentence does not put in words. */
function unshown(raw: string): number {
  const all = settings(raw);
  if (!all) return 1;
  const said = /^(target|enforcement|bypass_actors|conditions > ref_name > (include|exclude)|rules > (deletion|non_fast_forward|pull_request|required_status_checks|required_signatures) > type|rules > pull_request > parameters > (required_approving_review_count|require_last_push_approval))$/;
  return [...all.keys()].filter((k) => !said.test(k)).length;
}

/** One vault line's item ("Shelflip:private") in words, by kind. */
function item(kind: string, raw: string): string {
  if (kind === "repos") {
    const [repo, vis] = raw.split(":");
    return `${name(repo ?? "")} (${vis})`;
  }
  if (kind === "apps") {
    const m = /^(.+?)#\d+:(\w+):(.*)$/.exec(raw);
    return m ? `${name(m[1]!)}, on ${m[2] === "all" ? "all repositories" : "selected repositories"}: ${perms(m[3]!)}` : raw;
  }
  if (kind === "pats") return `a token belonging to ${name(raw.split(":")[0] ?? "")}`;
  if (kind === "deploy_keys") return `a key on ${name(raw.split(":")[0] ?? "")}`;
  if (kind === "rulesets") {
    const m = /^([^:]+):\d+:(\w+):(.*)$/.exec(raw);
    return m ? ruleset(name(m[1]!), m[2]!, m[3]!) : name(raw);
  }
  return name(raw);
}

/** The vault's change lines, grouped by kind, each item in words and marked New or Gone. */
export function plainChanges(lines: string[]): { heading: string; items: string[] }[] {
  const groups = new Map<string, { added: number; gone: number; items: string[] }>();
  for (const line of lines) {
    const m = /^(\w+) ([+-])(.*)$/.exec(line);
    const kind = m?.[1] ?? "other";
    const g = groups.get(kind) ?? { added: 0, gone: 0, items: [] };
    if (!m) g.items.push(name(line));
    else if (m[2] === "+") (g.added++, g.items.push(`New: ${item(kind, m[3]!)}`));
    else (g.gone++, g.items.push(`Gone: ${item(kind, m[3]!)}`));
    groups.set(kind, g);
  }
  // A changed ruleset arrives as Gone + New with the same repo and id: say, setting by setting, what
  // changed, so no weakening hides behind words that only cover some settings (Codex readable r1 #1).
  // A new ruleset says how many of its settings the words leave out.
  const rules = lines.filter((l) => /^rulesets [+-]/.test(l)).map((l) => /^rulesets ([+-])([^:]+:\d+):\w+:(.*)$/.exec(l));
  const rg = groups.get("rulesets");
  if (rg) {
    rg.items = rg.items.map((i, n) => {
      const m = rules[n];
      if (!m || m[1] !== "+") return i;
      const old = rules.find((o) => o?.[1] === "-" && o[2] === m[2]);
      if (old) {
        const diff = settingChanges(old[3]!, m[3]!);
        return `${i}. CHANGED: ${diff.join("; ") || "nothing the page can see"} (exact lines under Exact details)`;
      }
      const extra = unshown(m[3]!);
      return extra ? `${i}; plus ${extra} more setting${extra === 1 ? "" : "s"} these words leave out (see Exact details)` : i;
    });
  }
  // Any other change the words cannot show reads the same as New and Gone: flag it, never "no change".
  for (const [kind, g] of groups) {
    if (kind === "rulesets") continue;
    const said = (i: string) => i.replace(/^(New|Gone): /, "");
    const both = new Set(g.items.filter((i) => i.startsWith("New: ")).map(said).filter((t) => g.items.includes(`Gone: ${t}`)));
    g.items = g.items.map((i) => (both.has(said(i)) ? `${i} (CHANGED in a way these words do not show: read Exact details before approving)` : i));
  }
  // Last line of defence: every item is printable ASCII, whatever path its text came through (rule
  // types, setting names and values, permission names). Our own words are all ASCII.
  for (const g of groups.values()) g.items = g.items.map(ascii);
  return [...groups].map(([kind, g]) => ({
    heading: `${KINDS[kind] ?? kind}: ${[g.added && `${g.added} new`, g.gone && `${g.gone} gone`].filter(Boolean).join(", ") || "changed"}`,
    items: g.items,
  }));
}

/** "23 repositories, 2 people, ..." from the vault's counts. */
export function plainCounts(counts: Record<string, number>): string {
  return Object.entries(counts)
    .map(([k, n]) => `${n} ${(COUNTS[k] ?? [k, k])[n === 1 ? 0 : 1]}`)
    .join(", ");
}

/** The sentence Ben reads after his tap. */
export function baselineDone(r: GhBaselineResult): string {
  const lock = r.main.locked_to_passkey_now
    ? "The main GitHub App's key is now locked to your passkey: only your Face ID can unlock it."
    : "The main GitHub App's key was already locked to your passkey.";
  return `Done. ${lock} It still works. The read-only watcher was refused when it tried to give itself write access, as it should be. From tonight the nightly check expects: ${plainCounts(r.counts)}. Nothing else to do.`;
}
