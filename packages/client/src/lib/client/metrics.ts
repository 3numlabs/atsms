/**
 * Client instrumentation (dogfooding profiling): structured timing samples
 * from the SDK's two network seams (PDS reads/writes, transport posts) plus
 * operation-level spans with phase breakdowns. Samples go to the host's
 * `onMetric` sink and nowhere else — this is on-device measurement for a
 * privacy-first protocol, not telemetry; exporting is an explicit host act
 * (the reference CLI appends JSONL under its own profile dir).
 */

import type { PdsClient } from "@atsms/dcgka";

import type { EnvelopeTransport } from "../transport/envelope-transport.js";

export interface ATSMSMetric {
  /** Sample family: `pds.read` | `pds.write` | `transport.post` | `op`. */
  kind: "pds.read" | "pds.write" | "transport.post" | "op";
  /** The call (`getRecord`, `listRecords`, `deliverToUrl`, …) or operation
   *  (`open`, `addMember`, `send.oneShot`). */
  name: string;
  /** What it hit — a DID, collection, or URL; ops: the primary subject. */
  target?: string;
  ms: number;
  ok: boolean;
  /** Op samples: phase breakdown + counters (JSON-safe, flat). */
  detail?: Record<string, number | string>;
}

export type MetricSink = (m: ATSMSMetric) => void;

const timed = async <T>(
  emit: MetricSink,
  kind: ATSMSMetric["kind"],
  name: string,
  target: string,
  run: () => Promise<T>,
): Promise<T> => {
  const t0 = Date.now();
  try {
    const r = await run();
    emit({ kind, name, target, ms: Date.now() - t0, ok: true });
    return r;
  } catch (err) {
    emit({ kind, name, target, ms: Date.now() - t0, ok: false });
    throw err;
  }
};

/** Every read/write on the returned client emits a timing sample. */
export function instrumentPds(pds: PdsClient, emit: MetricSink): PdsClient {
  return {
    getRecord: (repo, c, rk) => timed(emit, "pds.read", "getRecord", `${repo} ${c}`, () => pds.getRecord(repo, c, rk)),
    listRecords: (repo, c) => timed(emit, "pds.read", "listRecords", `${repo} ${c}`, () => pds.listRecords(repo, c)),
    putRecord: (c, rk, value) => timed(emit, "pds.write", "putRecord", c, () => pds.putRecord(c, rk, value)),
    deleteRecord: (c, rk) => timed(emit, "pds.write", "deleteRecord", c, () => pds.deleteRecord(c, rk)),
  };
}

/** Every delivery on the returned transport emits a timing sample. */
export function instrumentTransport(transport: EnvelopeTransport, emit: MetricSink): EnvelopeTransport {
  return {
    ingressUrl: transport.ingressUrl,
    deliverToUrl: (url, env) => timed(emit, "transport.post", "deliverToUrl", url, () => transport.deliverToUrl(url, env)),
    deliverToDid: (did, env) => timed(emit, "transport.post", "deliverToDid", did, () => transport.deliverToDid(did, env)),
    start: (onEnvelope) => transport.start(onEnvelope),
    stop: () => transport.stop(),
  };
}

/** An operation span: `mark(phase)` fences phases; `end(detail)` emits. */
export function span(emit: MetricSink, name: string, target: string) {
  const t0 = Date.now();
  let last = t0;
  const phases: Record<string, number> = {};
  return {
    mark(phase: string): void {
      const now = Date.now();
      phases[`${phase}Ms`] = (phases[`${phase}Ms`] ?? 0) + (now - last);
      last = now;
    },
    end(detail: Record<string, number | string> = {}, ok = true): void {
      emit({ kind: "op", name, target, ms: Date.now() - t0, ok, detail: { ...phases, ...detail } });
    },
  };
}
