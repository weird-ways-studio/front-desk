// The vault's copies of the Observatory's card and receipt code (vault/src/cardcopy.ts) give the Observatory's own
// answers (REFINE-85818ab1 "Copy rule"). Fixtures: test/fixtures/card-vectors.json, made once by
// test/fixtures/make-card-vectors.ts running observatory @76f2837.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CARD_ELIGIBLE, CARD_MAX, CARD_RUN_MS, RECORDER_KEY, cardHashOf, challengeHash, parseManifest, receiptSealed, type Manifest } from "../vault/src/cardcopy.ts";
import { CARD_JOBS, CardBook } from "../vault/src/cards.ts";
import { MemoryCardStore } from "./cardsign.ts";
import { TEST_PIN } from "./vaultsign.ts";

const v = JSON.parse(readFileSync("test/fixtures/card-vectors.json", "utf8"));

test("vectors: parseManifest and cardHashOf give the Observatory's verdict and hash on every manifest", async () => {
  assert.ok(v.manifests.length >= 15);
  for (const c of v.manifests) {
    const m = c.name === "negative zero deadline" ? { ...c.manifest, deadline: -0 } : c.manifest;
    const parsed = parseManifest(m);
    assert.equal(typeof parsed === "string" ? parsed : null, c.verdict, c.name);
    assert.equal(typeof parsed === "string" ? null : await cardHashOf(parsed as Manifest), c.card_hash, c.name);
  }
});

test("vectors: challengeHash reads the same card hash out of a passkey answer", () => {
  for (const c of v.challenges) assert.equal(challengeHash({ client_data_json: c.client_data_json }) ?? null, c.hash, c.name);
});

test("vectors: receiptSealed gives the recorder's exact bytes, and the card book accepts its signature", async () => {
  const { sig: _sig, ...bare } = v.receipt.receipt;
  assert.equal(Buffer.from(receiptSealed(bare)).toString("base64"), v.receipt.sealed);
  const key = await crypto.subtle.importKey("raw", Buffer.from(v.receipt.key, "base64"), "Ed25519", false, ["verify"]);
  assert.ok(await crypto.subtle.verify("Ed25519", key, Buffer.from(v.receipt.receipt.sig, "base64"), receiptSealed(v.receipt.receipt)));
  assert.ok(new CardBook(new MemoryCardStore(), async () => ({}), TEST_PIN, { recorderKey: v.receipt.key }), "the book takes a raw base64 key");
});

test("vectors: the pinned recorder key, card list, run window and maximum equal the Observatory's", () => {
  assert.equal(RECORDER_KEY, v.recorder_key);
  assert.deepEqual([...CARD_ELIGIBLE], v.card_eligible);
  assert.deepEqual([...CARD_JOBS], v.card_eligible);
  assert.equal(CARD_RUN_MS, v.card_run_ms);
  assert.equal(CARD_MAX, v.card_max);
});
