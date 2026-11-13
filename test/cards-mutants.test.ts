// Each card-book safeguard, removed, makes its named test fail on an assertion (instruction.control-must-refuse-
// unsafe-case; REFINE-85818ab1 Outcome 2 "a committed mutant shown caught"). List: test/cards-mutants.json, each
// [id, file, find, replace, test name]. A mutant runs in a temp copy of the repo; it counts as caught only if its
// `find` occurs exactly once, and the one named test ran and failed with an AssertionError (not a load or type error).
// Limit, stated: a typecheck of the mutant is not run; a mutant that only breaks types is caught by its test or not at all.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Vault mutants run test/cards.test.ts; desk mutants (test/carddesk-mutants.json) and headcount-run mutants
// (test/headcountrun-mutants.json, card build 5 6ab972c8) and cf-key mutants (test/cfkeys-mutants.json, card 139071ea) name
// their own test file.
const mutants = [...JSON.parse(readFileSync("test/cards-mutants.json", "utf8")), ...JSON.parse(readFileSync("test/carddesk-mutants.json", "utf8")), ...JSON.parse(readFileSync("test/headcountrun-mutants.json", "utf8")), ...JSON.parse(readFileSync("test/cfkeys-mutants.json", "utf8"))] as [string, string, string, string, string, string?][];
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

for (const [id, file, find, replace, name, testFile = "test/cards.test.ts"] of mutants) {
  test(`mutant ${id} is caught by "${name}"`, { timeout: 60_000 }, () => {
    const dir = mkdtempSync(join(tmpdir(), "fd-mut-"));
    try {
      for (const d of ["src", "vault", "test", "scripts", "package.json", "tsconfig.json", "wrangler.jsonc"]) cpSync(d, join(dir, d), { recursive: true });
      symlinkSync(join(process.cwd(), "node_modules"), join(dir, "node_modules"));
      const src = readFileSync(file, "utf8");
      assert.equal(src.split(find).length - 1, 1, `${id}: the text to mutate occurs exactly once`);
      writeFileSync(join(dir, file), src.replace(find, replace));
      const r = spawnSync(process.execPath, ["--test", "--test-reporter=tap", `--test-name-pattern=^${esc(name)}$`, testFile], { cwd: dir, encoding: "utf8", env: { ...process.env, NODE_TEST_CONTEXT: undefined } });
      const out = r.stdout + r.stderr;
      assert.match(out, /^# tests 1$/m, `${id}: exactly the one named test ran\n${out.slice(-1500)}`);
      assert.match(out, /^# fail 1$/m, `${id}: SURVIVED -- the test still passes with the check removed`);
      assert.match(out, /AssertionError|ERR_ASSERTION|Missing expected rejection/, `${id}: failed, but not on an assertion\n${out.slice(-1500)}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
