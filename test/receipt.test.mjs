import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createSignedReceipt, input, publicKeyFromDid, run, verifyReceiptObject } from "../agent.mjs";

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(bytes) {
  let number = 0n;
  for (const byte of bytes) number = number * 256n + BigInt(byte);
  let encoded = "";
  while (number > 0n) {
    encoded = alphabet[Number(number % 58n)] + encoded;
    number /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = `1${encoded}`;
  }
  return encoded;
}

function identity() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(jwk.x, "base64url")]);
  return {
    privateKey,
    privateKeyJwk: privateKey.export({ format: "jwk" }),
    did: `did:key:z${encodeBase58(multicodec)}`,
  };
}

test("a signed health receipt verifies from its public DID", () => {
  const { privateKey, did } = identity();
  const receipt = createSignedReceipt({
    checkedAt: "2026-08-25T00:00:00.000Z",
    did,
    healthStatus: "healthy",
  }, privateKey);
  assert.equal(verifyReceiptObject(receipt), true);
  assert.equal(publicKeyFromDid(did).type, "public");
});

test("changing a signed receipt invalidates it", () => {
  const { privateKey, did } = identity();
  const receipt = createSignedReceipt({
    checkedAt: "2026-08-25T00:00:00.000Z",
    did,
    healthStatus: "healthy",
  }, privateKey);
  receipt.body.healthStatus = "recovered";
  assert.equal(verifyReceiptObject(receipt), false);
});

test("a malformed DID is rejected", () => {
  assert.throws(() => publicKeyFromDid("did:key:not-ed25519"), /Ed25519/);
});

test("an empty optional GitHub input uses its fallback", () => {
  const previous = process.env.INPUT_NOTE_URL;
  process.env.INPUT_NOTE_URL = "";
  try {
    assert.equal(input("note_url", { fallback: "derived-note-url" }), "derived-note-url");
  } finally {
    if (previous === undefined) delete process.env.INPUT_NOTE_URL;
    else process.env.INPUT_NOTE_URL = previous;
  }
});

test("a monitor run writes a verifiable status bundle", { concurrency: false }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "technocore-guardian-test-"));
  const outputs = join(directory, "outputs.txt");
  await writeFile(outputs, "", "utf8");
  const agent = identity();
  const originalFetch = globalThis.fetch;
  const originalEnvironment = { ...process.env };
  try {
    process.env.GITHUB_WORKSPACE = directory;
    process.env.GITHUB_OUTPUT = outputs;
    process.env.INPUT_PRIVATE_KEY_B64 = Buffer.from(JSON.stringify({
      did: agent.did,
      privateKeyJwk: agent.privateKeyJwk,
    }), "utf8").toString("base64");
    process.env.INPUT_DID = agent.did;
    process.env.INPUT_ROOM = "lobby";
    process.env.INPUT_PUBLISH_RECOVERY_NOTICE = "false";
    process.env.INPUT_OUTPUT_DIRECTORY = "status";
    globalThis.fetch = async (url) => {
      if (String(url).includes("/kv/")) return new Response(`${agent.did}\n`, { status: 200 });
      if (String(url).includes("/r/lobby")) {
        return new Response(JSON.stringify({ messages: [{ from: agent.did, text: "hello" }] }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    await run();
    const receipt = JSON.parse(await readFile(join(directory, "status", "health-receipt.json"), "utf8"));
    const badge = JSON.parse(await readFile(join(directory, "status", "badge.json"), "utf8"));
    const outputText = await readFile(outputs, "utf8");
    assert.equal(verifyReceiptObject(receipt), true);
    assert.equal(receipt.body.healthStatus, "healthy");
    assert.equal(badge.message, "healthy");
    assert.match(outputText, /health_status=healthy/);
  } finally {
    globalThis.fetch = originalFetch;
    process.env = originalEnvironment;
    await rm(directory, { recursive: true, force: true });
  }
});
