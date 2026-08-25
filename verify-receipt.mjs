import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { verifyReceiptObject } from "./agent.mjs";

const receiptPath = process.argv[2];
if (!receiptPath) {
  console.error("Usage: node verify-receipt.mjs <health-receipt.json>");
  process.exitCode = 2;
} else {
  try {
    const receipt = JSON.parse(await readFile(resolve(receiptPath), "utf8"));
    if (!verifyReceiptObject(receipt)) {
      console.error("INVALID: receipt signature does not match its DID and contents.");
      process.exitCode = 1;
    } else {
      console.log(`VALID: ${receipt.body.did} signed the ${receipt.body.healthStatus} receipt at ${receipt.body.checkedAt}.`);
    }
  } catch (error) {
    console.error(`ERROR: ${error.message}`);
    process.exitCode = 2;
  }
}
