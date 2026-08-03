// @ts-nocheck — headless two-session repro: reload → send over a SHARED
// IndexedDB (fake-indexeddb) against the real dev worker. Moved from
// atsms-web at its EOL (2026-08-03) — this is an SDK-level debugging asset:
// it exercises ATSMS restore-from-storage + transport against live infra
// with no browser. Usage: bun scripts/repro-two-session.ts <cli-profile-handle>
// (reads cert/key/session from ~/.atsms-cli/<handle>/).
import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import * as sms from "../dist/index.browser.js";

const API_URL = "https://atsms-api-dev.3numlabs.workers.dev";
const rng = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const handle = process.argv[2];
if (!handle) { console.log("usage: bun scripts/repro-two-session.ts <cli-profile-handle>"); process.exit(1); }
const dir = join(homedir(), ".atsms-cli", handle);
const certificatePEM = readFileSync(join(dir, "cert.pem"), "utf8");
const privateKeyPEM = readFileSync(join(dir, "key.pem"), "utf8");
const session = JSON.parse(readFileSync(join(dir, "session.json"), "utf8"));
const agent = new sms.AtpAgent({ service: "https://bsky.social" });
await agent.resumeSession(session);
const did = agent.session.did;

async function boot(label: string) {
  const pds = new sms.ATSMSPdsClient(agent, did);
  const storage = new sms.IndexedDBAdapter("repro2"); // SAME db both sessions
  const identity = await sms.ATSMSDeviceIdentity.load({ did, certificatePEM, privateKeyPEM, storage, rng });
  const transport = new sms.ATSMSWorkerEnvelopeTransport({
    apiUrl: API_URL, did, deviceFingerprint: identity.fingerprint, privateKeyPEM,
    resolveInboxUrl: sms.inboxUrlResolver(pds),
    onError: (e) => console.log(`[${label}] transport-error:`, e.message),
  });
  const atsms = await sms.ATSMS.create({
    identity, storage, transport, pds, rng,
    mailtoAddress: sms.didMailtoUri(did, "demo.atsms.at"),
    onEvent: (k, d) => console.log(`[${label}] ${k}: ${d}`),
  });
  return { atsms, storage };
}

console.log("== session 1: open ==");
const s1 = await boot("s1");
const peer = (await agent.resolveHandle({ handle: "chaosmokey.skyfi.social" })).data.did;
const convo = await s1.atsms.open({ members: [peer] });
console.log("opened", convo.id.slice(0, 8));
const blob1 = await s1.storage.loadEngineState(convo.id);
console.log("persisted engine-state bytes after open:", blob1?.length);
await s1.atsms.close();

console.log("== session 2: reload → restore → send ==");
const s2 = await boot("s2");
const handle = await s2.atsms.get(convo.id);
console.log("restored:", handle !== null);
try {
  await handle.send("post-reload send");
  console.log("SEND OK");
} catch (e) {
  console.log("SEND FAILED:", e.message);
}
await s2.atsms.close();
process.exit(0);
