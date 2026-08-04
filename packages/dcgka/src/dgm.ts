/**
 * The DGM (spec/dgm.md): a pure, deterministic function from the op DAG to a
 * membership view, with strong-remove semantics SR1–SR5 and the D11 role of
 * validity filter for the BeeKEM tree (Spike B, PR-1/PR-2).
 *
 * Remove-vs-remove concurrency is resolved on the *concurrent-kill graph*
 * (edge X→Y iff X targets Y's author and X ∥ Y): SCCs of that graph are
 * mutual-destruction sets — all alive (SR3, generalized to cycles); a remove
 * outside the cycle dies if an alive remove in an earlier SCC kills it (SR1
 * applied to removes); self-leaves are always alive (SR5). Everything else:
 * a member's ops die unless causally before an alive remove of that member
 * (SR1); invalid admissions cascade (SR2/SR4) via the admission check inside
 * the outer fixpoint.
 */

import { bytesEqual, bytesToHex } from './bytes.js';
import { ZERO32, membershipKey, sameMembership, type Membership } from './ids.js';
import { opKey, type Op } from './ops.js';

export interface DgmView {
  valid: Set<string>;
  members: Map<string, Membership>;
  admins: Set<string>;
}

export interface DgmSeed {
  members: Membership[];
  admins: string[];
}

interface Ctx {
  ops: Map<string, Op>;
  /** ancestor closure per op id (hex), exclusive of self. */
  anc: Map<string, Set<string>>;
  order: Op[];
}

/** Is this conversation a DM (its create op says so)? Membership is then fixed. */
function isDirectConversation(ctx: Ctx): boolean {
  for (const op of ctx.order) {
    if (op.payload.type === 'create') return op.payload.kind === 'dm';
  }
  return false;
}

function buildCtx(ops: Op[]): Ctx {
  const byId = new Map<string, Op>();
  for (const op of ops) byId.set(opKey(op.id), op);
  const depth = new Map<string, number>();
  const anc = new Map<string, Set<string>>();
  const resolve = (id: string, stack: Set<string>): number => {
    const cached = depth.get(id);
    if (cached !== undefined) return cached;
    if (stack.has(id)) throw new Error('dgm: dependency cycle');
    stack.add(id);
    const op = byId.get(id);
    if (op === undefined) {
      depth.set(id, 0);
      anc.set(id, new Set());
      stack.delete(id);
      return 0; // pruned behind a checkpoint
    }
    let d = 0;
    const a = new Set<string>();
    for (const dep of op.deps) {
      const dk = bytesToHex(dep);
      d = Math.max(d, resolve(dk, stack) + 1);
      a.add(dk);
      for (const x of anc.get(dk) ?? []) a.add(x);
    }
    depth.set(id, d);
    anc.set(id, a);
    stack.delete(id);
    return d;
  };
  for (const op of ops) resolve(opKey(op.id), new Set());
  const order = [...ops].sort((x, y) => {
    const dx = depth.get(opKey(x.id))!;
    const dy = depth.get(opKey(y.id))!;
    if (dx !== dy) return dx - dy;
    return opKey(x.id) < opKey(y.id) ? -1 : 1;
  });
  return { ops: byId, anc, order };
}

const precedes = (ctx: Ctx, a: string, b: string): boolean => ctx.anc.get(b)?.has(a) ?? false;
const concurrent = (ctx: Ctx, a: string, b: string): boolean =>
  a !== b && !precedes(ctx, a, b) && !precedes(ctx, b, a);

/**
 * Resolve remove-vs-remove concurrency: returns the alive subset of the
 * candidate removes (SR3/SR5 + SR1-on-removes via SCC condensation).
 */
function aliveRemoves(ctx: Ctx, candidates: Op[]): Set<string> {
  const ids = candidates.map((o) => opKey(o.id));
  const byId = new Map(candidates.map((o) => [opKey(o.id), o]));
  const isSelfLeave = (o: Op) =>
    o.payload.type === 'remove' && sameMembership(o.payload.membership, o.author);
  // kill edges among concurrent removes: X→Y iff X targets Y.author.
  const edges = new Map<string, Set<string>>(ids.map((i) => [i, new Set()]));
  for (const x of candidates) {
    if (x.payload.type !== 'remove') continue;
    const xk = opKey(x.id);
    const target = membershipKey(x.payload.membership);
    for (const y of candidates) {
      const yk = opKey(y.id);
      if (xk === yk) continue;
      if (membershipKey(y.author) === target && concurrent(ctx, xk, yk)) {
        edges.get(xk)!.add(yk);
      }
    }
  }
  // Kosaraju SCC.
  const visited = new Set<string>();
  const orderStack: string[] = [];
  const dfs1 = (v: string) => {
    const stack = [[v, edges.get(v)![Symbol.iterator]()] as [string, Iterator<string>]];
    visited.add(v);
    while (stack.length > 0) {
      const top = stack[stack.length - 1]!;
      const nxt = top[1].next();
      if (nxt.done) {
        orderStack.push(top[0]);
        stack.pop();
      } else if (!visited.has(nxt.value)) {
        visited.add(nxt.value);
        stack.push([nxt.value, edges.get(nxt.value)![Symbol.iterator]()]);
      }
    }
  };
  for (const i of ids) if (!visited.has(i)) dfs1(i);
  const redges = new Map<string, Set<string>>(ids.map((i) => [i, new Set()]));
  for (const [x, ys] of edges) for (const y of ys) redges.get(y)!.add(x);
  const sccOf = new Map<string, number>();
  let sccCount = 0;
  for (let i = orderStack.length - 1; i >= 0; i--) {
    const start = orderStack[i]!;
    if (sccOf.has(start)) continue;
    const stack = [start];
    sccOf.set(start, sccCount);
    while (stack.length > 0) {
      const v = stack.pop()!;
      for (const w of redges.get(v)!) {
        if (!sccOf.has(w)) {
          sccOf.set(w, sccCount);
          stack.push(w);
        }
      }
    }
    sccCount += 1;
  }
  const sccSize = new Map<number, number>();
  for (const [, s] of sccOf) sccSize.set(s, (sccSize.get(s) ?? 0) + 1);
  // Process SCCs in topological order of the condensation: Kosaraju numbers
  // source components first, so increasing scc id goes killers→victims.
  const byScc = new Map<number, string[]>();
  for (const [v, s] of sccOf) {
    if (!byScc.has(s)) byScc.set(s, []);
    byScc.get(s)!.push(v);
  }
  const alive = new Set<string>();
  const sccIds = [...byScc.keys()].sort((a, b) => a - b);
  for (const s of sccIds) {
    for (const v of byScc.get(s)!.sort()) {
      const op = byId.get(v)!;
      if (isSelfLeave(op)) {
        alive.add(v); // SR5: self-leave always lands
        continue;
      }
      const inCycle =
        sccSize.get(s)! > 1 || edges.get(v)!.has(v); // mutual set (SR3 generalized)
      if (inCycle) {
        alive.add(v);
        continue;
      }
      let killed = false;
      for (const [x, ys] of edges) {
        if (ys.has(v) && alive.has(x) && sccOf.get(x)! !== s) {
          killed = true;
          break;
        }
      }
      if (!killed) alive.add(v);
    }
  }
  return alive;
}

interface PassState {
  valid: Set<string>;
  admitted: Map<string, string>; // membershipKey → admitting op id
}

function pass(ctx: Ctx, seed: DgmSeed | undefined, prev: PassState | null): PassState {
  const valid = new Set<string>();
  const admitted = new Map<string, string>();
  const seedMembers = new Set((seed?.members ?? []).map(membershipKey));
  const isValidPrev = (id: string) => (prev === null ? true : prev.valid.has(id));

  // Stage 1: alive removes among prev-pass-valid candidates.
  const removeCandidates = ctx.order.filter(
    (o) => o.payload.type === 'remove' && isValidPrev(opKey(o.id)),
  );
  const alive = aliveRemoves(ctx, removeCandidates);
  const aliveRemovesOf = (mk: string): Op[] =>
    removeCandidates.filter(
      (o) =>
        alive.has(opKey(o.id)) &&
        o.payload.type === 'remove' &&
        membershipKey(o.payload.membership) === mk,
    );

  // Stage 2: topo walk.
  const membersAt = (at: string): { members: Map<string, Membership>; admins: Set<string> } => {
    const members = new Map<string, Membership>();
    const admins = new Set<string>(seed?.admins ?? []);
    for (const m of seed?.members ?? []) members.set(membershipKey(m), m);
    for (const op of ctx.order) {
      const k = opKey(op.id);
      if (k === at || !precedes(ctx, k, at)) continue;
      if (!valid.has(k)) continue;
      applyToView(op, members, admins);
    }
    return { members, admins };
  };

  for (const op of ctx.order) {
    const k = opKey(op.id);
    const p = op.payload;
    const authorMk = membershipKey(op.author);

    // Admission (SR2/SR4 cascade lives here: an invalid add admits no one).
    let authorOk: boolean;
    if (p.type === 'create') {
      authorOk = true;
    } else if (seedMembers.has(authorMk)) {
      authorOk = true;
    } else {
      const admittingId = admitted.get(authorMk);
      authorOk =
        admittingId !== undefined &&
        admittingId === bytesToHex(op.author.admittedBy) &&
        precedes(ctx, admittingId, k);
    }

    // SR1: removed authors.
    let removedOk = true;
    if (authorOk && p.type !== 'create') {
      for (const r of aliveRemovesOf(authorMk)) {
        const rk = opKey(r.id);
        if (rk === k) continue;
        if (p.type === 'remove') {
          if (precedes(ctx, rk, k)) removedOk = false; // concurrent handled by SCC stage
        } else if (!precedes(ctx, k, rk)) {
          removedOk = false;
        }
        if (!removedOk) break;
      }
      // A remove not alive in stage 1 is invalid outright.
      if (p.type === 'remove' && !alive.has(k)) removedOk = false;
    }

    // Authorization at causal position (dgm.md §4).
    let authzOk = true;
    if (authorOk && removedOk) {
      const view = membersAt(k);
      const authorDid = op.author.device.did;
      // A DM's membership is FIXED by its create op: exactly those two people,
      // for as long as it exists. Rejecting membership ops here (not merely in
      // the local builders) is what makes it an invariant rather than a
      // convention — no client can grow or shrink someone else's DM.
      const isDirect = isDirectConversation(ctx);
      switch (p.type) {
        case 'create':
          authzOk = true;
          break;
        case 'add': {
          // In a DM the set of PEOPLE is fixed by the create op; enrolling
          // another device of someone already present is still allowed.
          const knownDid = [...view.members.values()].some((m) => m.device.did === p.device.did);
          authzOk = (!isDirect || knownDid) && (p.device.did === authorDid || view.admins.has(authorDid));
          break;
        }
        case 'remove': {
          // …and the mirror: a DM participant's spare device may be revoked,
          // but never their last one (that would drop them from the DM).
          const remaining = [...view.members.values()].filter(
            (m) => m.device.did === p.membership.device.did,
          ).length;
          authzOk =
            (!isDirect || remaining > 1) &&
            (p.membership.device.did === authorDid || view.admins.has(authorDid));
          break;
        }
        case 'grantAdmin': {
          const granteeHasMember = [...view.members.values()].some((m) => m.device.did === p.did);
          authzOk = view.admins.has(authorDid) && granteeHasMember;
          break;
        }
        case 'revokeAdmin':
          authzOk = view.admins.has(authorDid) && !(view.admins.size === 1 && view.admins.has(p.did));
          break;
        default:
          authzOk = true;
      }
    }

    if (authorOk && removedOk && authzOk) {
      valid.add(k);
      if (p.type === 'create') {
        for (const d of p.initialDevices) {
          admitted.set(membershipKey({ device: d.device, admittedBy: op.id }), k);
        }
      } else if (p.type === 'add') {
        admitted.set(membershipKey({ device: p.device, admittedBy: op.id }), k);
      }
    }
  }
  return { valid, admitted };
}

function applyToView(op: Op, members: Map<string, Membership>, admins: Set<string>): void {
  const p = op.payload;
  if (p.type === 'create') {
    for (const d of p.initialDevices) {
      const m: Membership = { device: d.device, admittedBy: op.id };
      members.set(membershipKey(m), m);
    }
    for (const did of p.initialAdmins) admins.add(did);
  } else if (p.type === 'add') {
    const m: Membership = { device: p.device, admittedBy: op.id };
    members.set(membershipKey(m), m);
  } else if (p.type === 'remove') {
    members.delete(membershipKey(p.membership));
    const did = p.membership.device.did;
    if (![...members.values()].some((m) => m.device.did === did)) admins.delete(did);
  } else if (p.type === 'grantAdmin') {
    admins.add(p.did);
  } else if (p.type === 'revokeAdmin') {
    admins.delete(p.did);
  }
}

/** Batch evaluation (P1/P5) — fixpoint with a hard cap; instability surfaces. */
export function evaluate(opsIn: Op[], seed?: DgmSeed): DgmView {
  const normalized = opsIn.map(normalizeCreateAuthor);
  const ctx = buildCtx(normalized);
  let state: PassState | null = null;
  const cap = ctx.order.length + 2;
  for (let i = 0; ; i++) {
    const next = pass(ctx, seed, state);
    if (state !== null && setsEqual(state.valid, next.valid)) {
      state = next;
      break;
    }
    state = next;
    if (i >= cap) throw new Error('dgm: evaluation did not stabilize');
  }
  const members = new Map<string, Membership>();
  const admins = new Set<string>(seed?.admins ?? []);
  for (const m of seed?.members ?? []) members.set(membershipKey(m), m);
  for (const op of ctx.order) {
    if (state.valid.has(opKey(op.id))) applyToView(op, members, admins);
  }
  return { valid: state.valid, members, admins };
}

function setsEqual(a: Set<string>, b: Set<string>): boolean {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

/** Normalize a create author's zeroed admittedBy to the op id (wire-format §2). */
export function normalizeCreateAuthor(op: Op): Op {
  if (op.payload.type !== 'create' || !bytesEqual(op.author.admittedBy, ZERO32)) return op;
  return { ...op, author: { device: op.author.device, admittedBy: op.id } };
}
