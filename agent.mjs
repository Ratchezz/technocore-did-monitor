import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const RECEIPT_SCHEMA = "technocore-health-receipt/v1";
const RECEIPT_DOMAIN = `${RECEIPT_SCHEMA}\n`;
const DEFAULT_OUTPUT_DIRECTORY = "technocore-status";

export function input(name, { required = false, fallback = "" } = {}) {
  const supplied = process.env[`INPUT_${name.toUpperCase()}`] ?? process.env[name.toUpperCase()];
  const value = supplied === undefined || supplied === "" ? fallback : supplied;
  if (required && !value) throw new Error(`Missing required input: ${name}`);
  return value;
}

function booleanInput(name, fallback) {
  const value = input(name, { fallback: String(fallback) }).trim().toLowerCase();
  if (!["true", "false"].includes(value)) throw new Error(`${name} must be true or false.`);
  return value === "true";
}

async function setOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath) await appendFile(outputPath, `${name}=${value}\n`, "utf8");
}

async function requestText(url) {
  const response = await fetch(url, {
    headers: { "User-Agent": "Technocore-Guardian/2.0" },
    signal: AbortSignal.timeout(30_000),
  });
  return { status: response.status, body: await response.text() };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalReceiptPayload(body) {
  return Buffer.from(`${RECEIPT_DOMAIN}${JSON.stringify(body)}`, "utf8");
}

export function createSignedReceipt(body, privateKey) {
  return {
    schema: RECEIPT_SCHEMA,
    body,
    signature: {
      algorithm: "Ed25519",
      encoding: "base64url",
      value: sign(null, canonicalReceiptPayload(body), privateKey).toString("base64url"),
    },
  };
}

function decodeBase58(value) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let number = 0n;
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("DID contains an invalid base58btc character.");
    number = number * 58n + BigInt(index);
  }
  const bytes = [];
  while (number > 0n) {
    bytes.push(Number(number & 255n));
    number >>= 8n;
  }
  bytes.reverse();
  let leadingZeros = 0;
  while (leadingZeros < value.length && value[leadingZeros] === "1") leadingZeros += 1;
  return Buffer.concat([Buffer.alloc(leadingZeros), Buffer.from(bytes)]);
}

export function publicKeyFromDid(did) {
  if (!/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(did)) {
    throw new Error("Receipt DID is not an Ed25519 did:key value.");
  }
  const decoded = decodeBase58(did.slice("did:key:z".length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("Receipt DID does not contain an Ed25519 public key.");
  }
  return createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: decoded.subarray(2).toString("base64url"),
    },
    format: "jwk",
  });
}

export function verifyReceiptObject(receipt) {
  if (receipt?.schema !== RECEIPT_SCHEMA || receipt?.signature?.algorithm !== "Ed25519") {
    return false;
  }
  const publicKey = publicKeyFromDid(receipt.body?.did ?? "");
  return verify(
    null,
    canonicalReceiptPayload(receipt.body),
    publicKey,
    Buffer.from(receipt.signature.value ?? "", "base64url"),
  );
}

function safeOutputDirectory(value) {
  const workspace = resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  const directory = resolve(workspace, value || DEFAULT_OUTPUT_DIRECTORY);
  const prefix = workspace.endsWith("\\") || workspace.endsWith("/") ? workspace : `${workspace}\\`;
  if (directory !== workspace && !directory.startsWith(prefix) && !directory.startsWith(`${workspace}/`)) {
    throw new Error("output_directory must remain inside GITHUB_WORKSPACE.");
  }
  return directory;
}

function htmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function statusColor(healthStatus) {
  if (healthStatus === "healthy") return "brightgreen";
  if (healthStatus === "recovered") return "blue";
  return "red";
}

function statusHtml(status) {
  const color = status.healthStatus === "healthy" ? "#2da44e" : status.healthStatus === "recovered" ? "#0969da" : "#cf222e";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Technocore Guardian status</title>
<style>body{font:16px system-ui;max-width:760px;margin:4rem auto;padding:0 1rem;color:#1f2328}main{border:1px solid #d0d7de;border-radius:14px;padding:2rem}h1{margin-top:0}.state{color:${color};font-weight:700;text-transform:uppercase}dt{font-weight:600;margin-top:1rem}dd{margin:.25rem 0;overflow-wrap:anywhere}footer{margin-top:2rem;color:#656d76;font-size:.9rem}</style></head>
<body><main><h1>Technocore Guardian</h1><p class="state">${htmlEscape(status.healthStatus)}</p><dl>
<dt>DID</dt><dd><code>${htmlEscape(status.did)}</code></dd><dt>Checked</dt><dd>${htmlEscape(status.checkedAt)}</dd>
<dt>DID note</dt><dd>${htmlEscape(status.noteStatus)}</dd><dt>Room</dt><dd><code>${htmlEscape(status.room)}</code></dd>
<dt>Receipt SHA-256</dt><dd><code>${htmlEscape(status.receiptSha256 || "unavailable")}</code></dd></dl>
<footer>Generated without routine Technocore heartbeat messages.</footer></main></body></html>\n`;
}

async function writeStatusBundle(directory, { receipt, receiptJson, receiptSha256, event }) {
  await mkdir(directory, { recursive: true });
  const receiptPath = resolve(directory, "health-receipt.json");
  const eventPath = resolve(directory, "incident-event.json");
  const status = {
    schema: "technocore-guardian-status/v1",
    did: event.did,
    checkedAt: event.checkedAt,
    healthStatus: event.healthStatus,
    noteStatus: event.noteStatus,
    room: event.room,
    incident: event.incident,
    receiptSha256,
  };
  const badge = {
    schemaVersion: 1,
    label: "Technocore DID",
    message: event.healthStatus,
    color: statusColor(event.healthStatus),
  };
  if (receipt) {
    await writeFile(receiptPath, receiptJson, "utf8");
  } else {
    await writeFile(receiptPath, `${JSON.stringify({
      schema: "technocore-health-receipt/unavailable",
      checkedAt: event.checkedAt,
      did: event.did,
      healthStatus: event.healthStatus,
      reason: event.error,
      signed: false,
    }, null, 2)}\n`, "utf8");
  }
  await Promise.all([
    writeFile(resolve(directory, "status.json"), `${JSON.stringify(status, null, 2)}\n`, "utf8"),
    writeFile(resolve(directory, "badge.json"), `${JSON.stringify(badge, null, 2)}\n`, "utf8"),
    writeFile(eventPath, `${JSON.stringify(event, null, 2)}\n`, "utf8"),
    writeFile(resolve(directory, "index.html"), statusHtml(status), "utf8"),
  ]);
  return { receiptPath, eventPath };
}

function runnerEvidence() {
  return {
    repository: process.env.GITHUB_REPOSITORY || null,
    workflow: process.env.GITHUB_WORKFLOW || null,
    runId: process.env.GITHUB_RUN_ID || null,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT || null,
    commit: process.env.GITHUB_SHA || null,
  };
}

function normalizeError(error) {
  if (error?.name === "TimeoutError" || error?.name === "AbortError") return "Technocore request timed out.";
  return String(error?.message || error || "Unknown monitor failure").slice(0, 500);
}

async function publishOutputs(values) {
  await Promise.all(Object.entries(values).map(([name, value]) => setOutput(name, value)));
}

async function writeSummary(event, receiptSha256 = "") {
  if (!process.env.GITHUB_STEP_SUMMARY) return;
  const lines = [
    "## Technocore Guardian",
    "",
    `- Health: **${event.healthStatus}**`,
    `- DID: \`${event.did}\``,
    `- Checked: ${event.checkedAt}`,
    `- DID note: ${event.noteStatus}`,
    `- Room: \`${event.room}\``,
    `- Incident: ${event.incident}`,
  ];
  if (receiptSha256) lines.push(`- Signed receipt SHA-256: \`${receiptSha256}\``);
  if (event.error) lines.push(`- Error: ${event.error}`);
  await appendFile(process.env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`, "utf8");
}

export async function run() {
  const checkedAt = new Date().toISOString();
  const expectedDid = input("did", { required: true }).trim();
  const room = input("room", { fallback: "lobby" }).trim();
  const outputDirectory = safeOutputDirectory(input("output_directory", { fallback: DEFAULT_OUTPUT_DIRECTORY }).trim());
  let noteStatus = "unknown";
  let messagesChecked = 0;
  let publishedRecoveryNotice = false;

  try {
    if (!/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(expectedDid)) {
      throw new Error("did must be an Ed25519 did:key value.");
    }
    if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(room)) {
      throw new Error("room does not match Technocore's room-name rules.");
    }

    const encodedSecret = input("private_key_b64", { required: true });
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
    const selfTest = Buffer.from("technocore-guardian-self-test", "utf8");
    const selfTestSignature = sign(null, selfTest, privateKey);
    if (!verify(null, selfTest, publicKey, selfTestSignature)) throw new Error("Ed25519 key self-test failed.");

    const fingerprint = sha256(expectedDid).slice(0, 16);
    const derivedNoteUrl = `https://technocore.chat/kv/did-${fingerprint.slice(0, 2)}/${fingerprint.slice(2)}`;
    const noteUrl = input("note_url", { fallback: derivedNoteUrl }).trim();
    if (!noteUrl.startsWith("https://technocore.chat/kv/")) {
      throw new Error("note_url must use https://technocore.chat/kv/.");
    }

    const currentNote = await requestText(noteUrl);
    const noteLines = currentNote.body.split(/\r?\n/).map((line) => line.trim());
    const noteMatchesIdentity = noteLines.includes(expectedDid);
    noteStatus = "present";
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
    if (roomResponse.status !== 200) throw new Error(`Could not read room ${room} (HTTP ${roomResponse.status}).`);
    const parsedRoom = JSON.parse(roomResponse.body);
    const messages = Array.isArray(parsedRoom) ? parsedRoom : parsedRoom.messages;
    if (!Array.isArray(messages)) throw new Error("Technocore returned an unexpected room response.");
    messagesChecked = messages.length;

    if (noteStatus === "restored" && booleanInput("publish_recovery_notice", true)) {
      const nonce = String(Date.now());
      const text = "Technocore Guardian restored its public DID note and verified its Ed25519 identity.";
      const signature = sign(null, Buffer.from(`${room}|${nonce}|${text}`, "utf8"), privateKey).toString("base64url");
      const messageUrl = `https://technocore.chat/r/${room}/say-signed/${encodeURIComponent(expectedDid)}/${signature}/${nonce}/${encodeURIComponent(text)}`;
      const published = await requestText(messageUrl);
      if (![200, 201].includes(published.status)) {
        throw new Error(`The note was restored, but the signed notice failed (HTTP ${published.status}).`);
      }
      publishedRecoveryNotice = true;
    }

    const healthStatus = noteStatus === "restored" ? "recovered" : "healthy";
    const body = {
      checkedAt,
      did: expectedDid,
      fingerprint,
      healthStatus,
      keySelfTest: "passed",
      note: { url: noteUrl, status: noteStatus },
      room: { name: room, status: "reachable", messagesChecked },
      recoveryNoticePublished: publishedRecoveryNotice,
      evidence: runnerEvidence(),
    };
    const receipt = createSignedReceipt(body, privateKey);
    if (!verifyReceiptObject(receipt)) throw new Error("Generated health receipt failed local verification.");
    const receiptJson = JSON.stringify(receipt, null, 2);
    const receiptSha256 = sha256(receiptJson);
    const event = {
      schema: "technocore-guardian-event/v1",
      checkedAt,
      did: expectedDid,
      healthStatus,
      noteStatus,
      room,
      incident: noteStatus === "restored" ? "did_note_recovered" : "none",
      receiptSha256,
      evidence: runnerEvidence(),
    };
    const paths = await writeStatusBundle(outputDirectory, { receipt, receiptJson, receiptSha256, event });
    await publishOutputs({
      health_status: healthStatus,
      note_status: noteStatus,
      messages_checked: messagesChecked,
      published_recovery_notice: publishedRecoveryNotice,
      checked_at: checkedAt,
      incident: event.incident,
      receipt_path: paths.receiptPath,
      receipt_sha256: receiptSha256,
      status_directory: outputDirectory,
    });
    await writeSummary(event, receiptSha256);
    console.log(JSON.stringify({ ok: true, ...event }));
  } catch (error) {
    const failure = normalizeError(error);
    const event = {
      schema: "technocore-guardian-event/v1",
      checkedAt,
      did: expectedDid || "unavailable",
      healthStatus: "unhealthy",
      noteStatus,
      room: room || "unavailable",
      incident: "monitor_failure",
      error: failure,
      evidence: runnerEvidence(),
    };
    await writeStatusBundle(outputDirectory, { receipt: null, receiptJson: "", receiptSha256: "", event });
    await publishOutputs({
      health_status: "unhealthy",
      note_status: noteStatus,
      messages_checked: messagesChecked,
      published_recovery_notice: publishedRecoveryNotice,
      checked_at: checkedAt,
      incident: event.incident,
      receipt_path: "",
      receipt_sha256: "",
      status_directory: outputDirectory,
    });
    await writeSummary(event);
    throw new Error(failure);
  }
}

const isEntrypoint = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isEntrypoint) await run();
