/**
 * AT Protocol implementation of the `@atsms/dcgka` `PdsClient` seam.
 *
 * The dcgka engine stays free of `@atproto/api`; this adapter wires its
 * put/get/delete/list surface onto an authenticated `AtpAgent`. Bytes need no
 * special handling: `@atproto/api`'s XRPC client encodes bodies with `stringifyLex`
 * (Uint8Array → `{$bytes}`) and decodes responses with `jsonToLex` (`{$bytes}` →
 * Uint8Array), so records with `Uint8Array` fields (signedPrekey, bundleSig)
 * round-trip transparently.
 *
 * Writes go to the authenticated user's own repo; reads resolve the target DID's
 * PDS (did:plc and did:web both supported — the latter fixes the prototype's
 * plc-only gap).
 */

import { AtpAgent } from "@atproto/api";
import type { PdsClient, PdsRecordView, PutResult } from "@atsms/dcgka";

interface DidDocument {
  service?: Array<{
    id: string;
    type: string;
    serviceEndpoint: string | Record<string, unknown>;
  }>;
}

export interface ATSMSPdsClientOptions {
  /** PLC directory base URL (default https://plc.directory). */
  plcDirectoryUrl?: string;
}

export class ATSMSPdsClient implements PdsClient {
  private readonly readAgents = new Map<string, AtpAgent>();
  private readonly plcDirectoryUrl: string;

  constructor(
    private readonly agent: AtpAgent,
    private readonly myDid: string,
    options: ATSMSPdsClientOptions = {},
  ) {
    this.plcDirectoryUrl = options.plcDirectoryUrl ?? "https://plc.directory";
  }

  async putRecord(collection: string, rkey: string, value: unknown): Promise<PutResult> {
    const res = await this.agent.com.atproto.repo.putRecord({
      repo: this.myDid,
      collection,
      rkey,
      record: value as Record<string, unknown>,
    });
    return { uri: res.data.uri, cid: res.data.cid };
  }

  async deleteRecord(collection: string, rkey: string): Promise<void> {
    await this.agent.com.atproto.repo.deleteRecord({ repo: this.myDid, collection, rkey });
  }

  async getRecord(repo: string, collection: string, rkey: string): Promise<PdsRecordView | null> {
    const agent = await this.readAgentFor(repo);
    try {
      const res = await agent.com.atproto.repo.getRecord({ repo, collection, rkey });
      return { uri: res.data.uri, cid: res.data.cid ?? undefined, value: res.data.value };
    } catch (err) {
      if (isRecordNotFound(err)) return null;
      throw err;
    }
  }

  async listRecords(repo: string, collection: string): Promise<PdsRecordView[]> {
    const agent = await this.readAgentFor(repo);
    const res = await agent.com.atproto.repo.listRecords({ repo, collection, limit: 100 });
    return res.data.records.map((r) => ({ uri: r.uri, cid: r.cid, value: r.value }));
  }

  /** Authenticated agent for our own repo; an unauthenticated PDS agent (cached) for others. */
  private async readAgentFor(did: string): Promise<AtpAgent> {
    if (did === this.myDid) return this.agent;
    const cached = this.readAgents.get(did);
    if (cached) return cached;
    const pdsUrl = await resolveDidToPds(did, this.plcDirectoryUrl);
    const agent = new AtpAgent({ service: pdsUrl });
    this.readAgents.set(did, agent);
    return agent;
  }
}

/** Resolve a DID to its AT Protocol PDS endpoint (did:plc via the PLC directory, did:web via well-known). */
export async function resolveDidToPds(
  did: string,
  plcDirectoryUrl = "https://plc.directory",
): Promise<string> {
  let doc: DidDocument;
  if (did.startsWith("did:plc:")) {
    const res = await fetch(`${plcDirectoryUrl}/${encodeURIComponent(did)}`);
    if (!res.ok) throw new Error(`PLC resolution failed for ${did}: ${res.status}`);
    doc = (await res.json()) as DidDocument;
  } else if (did.startsWith("did:web:")) {
    const res = await fetch(didWebToUrl(did));
    if (!res.ok) throw new Error(`did:web resolution failed for ${did}: ${res.status}`);
    doc = (await res.json()) as DidDocument;
  } else {
    throw new Error(`Unsupported DID method: ${did}`);
  }
  const svc = (doc.service ?? []).find(
    (s) => s.id.endsWith("#atproto_pds") || s.type === "AtprotoPersonalDataServer",
  );
  if (!svc || typeof svc.serviceEndpoint !== "string") {
    throw new Error(`No AT Protocol PDS in DID document for ${did}`);
  }
  return svc.serviceEndpoint;
}

/** did:web:host → https://host/.well-known/did.json ; did:web:host:a:b → https://host/a/b/did.json (RFC). */
function didWebToUrl(did: string): string {
  const parts = did.slice("did:web:".length).split(":").map(decodeURIComponent);
  const host = parts[0];
  return parts.length === 1
    ? `https://${host}/.well-known/did.json`
    : `https://${host}/${parts.slice(1).join("/")}/did.json`;
}

function isRecordNotFound(err: unknown): boolean {
  const e = err as { error?: string; message?: string } | null;
  if (!e) return false;
  if (e.error === "RecordNotFound") return true;
  return typeof e.message === "string" && /could not locate record|record not found/i.test(e.message);
}
