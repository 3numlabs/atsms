/**
 * ATSMSWorkerEnvelopeTransport against a faked worker (injected fetch):
 * outbound POST bodies, inbox-record routing, and the backfill drain's
 * handle-then-delete contract (inbound-delivery.md §4).
 */

import { describe, expect, test } from "bun:test";

import { ATSMSWorkerEnvelopeTransport } from "../lib/transport/envelope-transport.js";
import { generateTestEndpointCertificate } from "./test-certificates.js";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

/** A minimal fake worker: records requests, serves a mutable envelope inbox. */
function fakeWorker() {
  const requests: Array<{ url: string; method: string; body?: unknown }> = [];
  const inbox: Array<{ id: string; seq: number; messageType: string; encryptedContent: string }> = [];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    requests.push({ url, method, body: init?.body === undefined ? undefined : JSON.parse(init.body as string) });
    if (method === "POST") return Response.json({ success: true });
    // The real worker's list returns METADATA ONLY — content needs the per-message GET.
    if (url.includes("/list")) {
      return Response.json({ messages: inbox.map(({ id, seq, messageType }) => ({ id, seq, messageType })) });
    }
    if (method === "DELETE") {
      const id = url.split("/").pop()!;
      const i = inbox.findIndex((m) => m.id === id);
      if (i >= 0) inbox.splice(i, 1);
      return Response.json({ success: true });
    }
    if (method === "GET") {
      const id = url.split("/").pop()!;
      const msg = inbox.find((m) => m.id === id);
      // The real API worker wraps the per-message GET: { message: {...} }.
      if (msg !== undefined) return Response.json({ message: msg });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }) as typeof fetch;
  return { requests, inbox, fetchFn };
}

// A real key PEM: the drain path mints worker JWTs (Authorization header).
const KEY_PEM = (await generateTestEndpointCertificate("did:plc:me", "me.example")).privateKey;

function transportOver(w: ReturnType<typeof fakeWorker>, resolveInboxUrl = async (_did: string): Promise<string | null> => null) {
  const t = new ATSMSWorkerEnvelopeTransport({
    apiUrl: "https://worker.test",
    did: "did:plc:me",
    deviceFingerprint: "abc123",
    privateKeyPEM: KEY_PEM,
    resolveInboxUrl,
    fetchFn: w.fetchFn,
    webSocket: false,
  });
  return t;
}

describe("ATSMSWorkerEnvelopeTransport", () => {
  test("ingressUrl is the worker's per-DID anonymous intake", () => {
    const t = transportOver(fakeWorker());
    expect(t.ingressUrl).toBe("https://worker.test/inbox/did%3Aplc%3Ame");
  });

  test("deliverToUrl POSTs { envelope: base64 } to the exact URL", async () => {
    const w = fakeWorker();
    const t = transportOver(w);
    await t.deliverToUrl("https://other.example/inbox/did%3Aplc%3Abob", enc("sealed!"));
    expect(w.requests).toHaveLength(1);
    expect(w.requests[0]).toEqual({
      url: "https://other.example/inbox/did%3Aplc%3Abob",
      method: "POST",
      body: { envelope: b64(enc("sealed!")) },
    });
  });

  test("deliverToDid routes via the resolved at.atsms.inbox https endpoint", async () => {
    const w = fakeWorker();
    const t = transportOver(w, async (did) => `https://relay.example/inbox/${encodeURIComponent(did)}`);
    await t.deliverToDid("did:plc:bob", enc("hi"));
    expect(w.requests[0]!.url).toBe("https://relay.example/inbox/did%3Aplc%3Abob");
  });

  test("deliverToDid fails loudly when only the mailto floor exists", async () => {
    const t = transportOver(fakeWorker(), async () => null);
    await expect(t.deliverToDid("did:plc:bob", enc("hi"))).rejects.toThrow(/no https inbox endpoint/);
  });

  test("drain hands each envelope to the handler, then deletes it (ack-on-success)", async () => {
    const w = fakeWorker();
    w.inbox.push(
      { id: "m1", seq: 1, messageType: "atsms-envelope", encryptedContent: b64(enc("env-1")) },
      { id: "m2", seq: 2, messageType: "atsms-envelope", encryptedContent: b64(enc("env-2")) },
    );
    const got: string[] = [];
    const t = transportOver(w);
    await t.start(async (envelope) => {
      got.push(dec(envelope));
    });
    await t.stop();
    expect(got).toEqual(["env-1", "env-2"]);
    expect(w.inbox).toHaveLength(0); // both acked (deleted)
    const listCalls = w.requests.filter((r) => r.url.includes("/list"));
    expect(listCalls[0]!.url).toContain("type=atsms-envelope");
  });

  test("a failing handler leaves the envelope in the inbox for the next drain", async () => {
    const w = fakeWorker();
    w.inbox.push({ id: "m1", seq: 1, messageType: "atsms-envelope", encryptedContent: b64(enc("poison")) });
    const t = transportOver(w);
    let calls = 0;
    await t.start(async () => {
      calls += 1;
      throw new Error("dispatcher exploded");
    });
    await t.stop();
    expect(calls).toBe(1);
    expect(w.inbox).toHaveLength(1); // NOT deleted — redelivered on the next drain
  });
});
