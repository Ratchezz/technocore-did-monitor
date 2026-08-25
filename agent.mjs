import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { appendFile } from "node:fs/promises";

function input(name, { required = false, fallback = "" } = {}) {
  const value = process.env[`INPUT_${name.toUpperCase()}`] ?? process.env[name.toUpperCase()] ?? fallback;
  if (required && !value) throw new Error(`Missing required input: ${name}`);
  return value;
}

function booleanInput(name, fallback) {
  const value = input(name, { fallback: String(fallback) }).trim().toLowerCase();
  if (!["true", "false"].includes(value)) throw new Error(`${name} must be true or false.`);
  return value === "true";
}

function setOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath) return appendFile(outputPath, `${name}=${value}\n`, "utf8");
}

async function requestText(url) {
  const response = await fetch(url, {
    headers: { "User-Agent": "Technocore-DID-Monitor/1.0" },
    signal: AbortSignal.timeout(30_000),
  });
  return { status: response.status, body: await response.text() };
}

const encodedSecret = input("private_key_b64", { required: true });
const expectedDid = input("did", { required: true }).trim();
const room = input("room", { fallback: "lobby" }).trim();
const shouldPublishRecoveryNotice = booleanInput("publish_recovery_notice", true);

if (!/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(expectedDid)) {
  throw new Error("did must be an Ed25519 did:key value.");
}
if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(room)) {
  throw new Error("room does not match Technocore's room-name rules.");
}

let privateRecord;
try {
  privateRecord = JSON.parse(Buffer.from(encodedSecret, "base64").toString("utf8"));
} catch {
  throw new Error("private_key_b64 is not a valid base64-encoded JSON identity file.");
}

if (privateRecord.did !== expectedDid || !privateRecord.privateKeyJwk?.d) {
  throw new Error("The secret identity does not match the configured public DID.");
}

const privateKey = createPrivateKey({ key: privateRecord.privateKeyJwk, format: "jwk" });
const publicKey = createPublicKey(privateKey);
const selfTest = Buffer.from("technocore-did-monitor-self-test", "utf8");
const selfTestSignature = sign(null, selfTest, privateKey);
if (!verify(null, selfTest, publicKey, selfTestSignature)) {
  throw new Error("Ed25519 key self-test failed.");
}

const fingerprint = createHash("sha256").update(expectedDid, "utf8").digest("hex").slice(0, 16);
const derivedNoteUrl = `https://technocore.chat/kv/did-${fingerprint.slice(0, 2)}/${fingerprint.slice(2)}`;
const noteUrl = input("note_url", { fallback: derivedNoteUrl }).trim();
if (!noteUrl.startsWith("https://technocore.chat/kv/")) {
  throw new Error("note_url must use https://technocore.chat/kv/.");
}

const currentNote = await requestText(noteUrl);
const noteLines = currentNote.body.split(/\r?\n/).map((line) => line.trim());
const noteMatchesIdentity = noteLines.includes(expectedDid);
let noteStatus = "present";

if (currentNote.status === 200 && !noteMatchesIdentity) {
  throw new Error("The configured note contains a different value; refusing to overwrite it.");
}
if (currentNote.status === 404) {
  const restoreUrl = `${noteUrl}/set/${encodeURIComponent(expectedDid)}?if_absent=1`;
  const restored = await requestText(restoreUrl);
  if (![200, 201].includes(restored.status)) {
    throw new Error(`Could not restore the public DID note (HTTP ${restored.status}).`);
  }
  noteStatus = "restored";
} else if (currentNote.status !== 200) {
  throw new Error(`Could not read the public DID note (HTTP ${currentNote.status}).`);
}

const roomResponse = await requestText(`https://technocore.chat/r/${room}?format=json&limit=200`);
if (roomResponse.status !== 200) {
  throw new Error(`Could not read room ${room} (HTTP ${roomResponse.status}).`);
}
const parsedRoom = JSON.parse(roomResponse.body);
const messages = Array.isArray(parsedRoom) ? parsedRoom : parsedRoom.messages;
if (!Array.isArray(messages)) throw new Error("Technocore returned an unexpected room response.");

let publishedRecoveryNotice = false;
if (noteStatus === "restored" && shouldPublishRecoveryNotice) {
  const nonce = String(Date.now());
  const text = "Technocore DID monitor restored its public identity note and verified its Ed25519 key.";
  const payload = Buffer.from(`${room}|${nonce}|${text}`, "utf8");
  const signature = sign(null, payload, privateKey).toString("base64url");
  const messageUrl = `https://technocore.chat/r/${room}/say-signed/${encodeURIComponent(expectedDid)}/${signature}/${nonce}/${encodeURIComponent(text)}`;
  const published = await requestText(messageUrl);
  if (![200, 201].includes(published.status)) {
    throw new Error(`The note was restored, but the signed notice failed (HTTP ${published.status}).`);
  }
  publishedRecoveryNotice = true;
}

await Promise.all([
  setOutput("note_status", noteStatus),
  setOutput("messages_checked", messages.length),
  setOutput("published_recovery_notice", publishedRecoveryNotice),
]);

const summary = {
  ok: true,
  did: expectedDid,
  keySelfTest: "passed",
  noteStatus,
  room,
  messagesChecked: messages.length,
  publishedRecoveryNotice,
};
console.log(JSON.stringify(summary));

if (process.env.GITHUB_STEP_SUMMARY) {
  await appendFile(
    process.env.GITHUB_STEP_SUMMARY,
    `## Technocore DID monitor\n\n- DID: \`${expectedDid}\`\n- Key self-test: passed\n- DID note: ${noteStatus}\n- Room: \`${room}\`\n- Messages checked: ${messages.length}\n- Recovery notice published: ${publishedRecoveryNotice}\n`,
    "utf8",
  );
}

