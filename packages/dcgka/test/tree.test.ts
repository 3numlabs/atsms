import { describe, expect, it } from 'vitest';
import { blake3 } from '@noble/hashes/blake3';
import { BeeKem, type PathChange } from '../src/tree.js';
import { ShareKeyMap, shareNodeKey } from '../src/keys.js';
import { generateShareSecretKey, shareKeyOf, type Csprng } from '../src/keyhive.js';
import { bytesToHex } from '../src/bytes.js';

/** Deterministic test csprng: BLAKE3 counter stream from a label. */
function testRng(label: string): Csprng {
  let ctr = 0;
  return (n: number) => blake3(new TextEncoder().encode(`${label}:${ctr++}`), { dkLen: n });
}

const DOC_ID = blake3(new TextEncoder().encode('doc'), { dkLen: 32 });
const memberId = (i: number) => blake3(new TextEncoder().encode(`member-${i}`), { dkLen: 32 });

interface Member {
  id: Uint8Array;
  sks: ShareKeyMap;
  leafPk: Uint8Array;
  rng: Csprng;
}

function makeMember(i: number): Member {
  const rng = testRng(`m${i}`);
  const sk = generateShareSecretKey(rng);
  const pk = shareKeyOf(sk);
  const sks = new ShareKeyMap();
  sks.insert(pk, sk);
  return { id: memberId(i), sks, leafPk: pk, rng };
}

/** Build a tree with n members; returns [tree, members]. */
function buildTree(n: number): [BeeKem, Member[]] {
  const members = Array.from({ length: n }, (_, i) => makeMember(i));
  const tree = new BeeKem(DOC_ID, members[0]!.id, members[0]!.leafPk);
  for (let i = 1; i < n; i++) tree.pushLeaf(members[i]!.id, shareNodeKey(members[i]!.leafPk));
  return [tree, members];
}

/** Rotate `m`'s leaf and encrypt its path; returns [rootSecret, pathChange]. */
function update(tree: BeeKem, m: Member): [Uint8Array, PathChange] {
  const newSk = generateShareSecretKey(m.rng);
  const newPk = shareKeyOf(newSk);
  m.sks.insert(newPk, newSk);
  return tree.encryptPath(m.id, newPk, m.sks, m.rng);
}

describe('BeeKem tree', () => {
  it('single member: update with blank sibling (empty resolution), encrypter shortcut', () => {
    const [tree, [m0]] = buildTree(1);
    expect(tree.hasRootKey()).toBe(false);
    const [root] = update(tree, m0!);
    expect(tree.hasRootKey()).toBe(true);
    const derived = tree.decryptTreeSecret(m0!.id, m0!.sks);
    expect(bytesToHex(derived)).toBe(bytesToHex(root));
  });

  for (const n of [2, 3, 5, 9]) {
    it(`n=${n}: every member derives the encrypter's root secret`, () => {
      const [tree, members] = buildTree(n);
      expect(tree.hasRootKey()).toBe(false); // adds blanked paths
      const [root] = update(tree, members[0]!);
      expect(tree.hasRootKey()).toBe(true);
      for (const m of members) {
        expect(bytesToHex(tree.decryptTreeSecret(m.id, m.sks))).toBe(bytesToHex(root));
      }
    });
  }

  it('sequential updates by different members keep converging', () => {
    const [tree, members] = buildTree(4);
    let root: Uint8Array | null = null;
    for (const updater of [members[0]!, members[2]!, members[3]!, members[1]!]) {
      [root] = update(tree, updater);
      for (const m of members) {
        expect(bytesToHex(tree.decryptTreeSecret(m.id, m.sks))).toBe(bytesToHex(root));
      }
    }
  });

  it('add blanks the root; the next update readmits everyone incl. the joiner', () => {
    const [tree, members] = buildTree(3);
    update(tree, members[0]!);
    expect(tree.hasRootKey()).toBe(true);
    const m3 = makeMember(3);
    tree.pushLeaf(m3.id, shareNodeKey(m3.leafPk));
    expect(tree.hasRootKey()).toBe(false); // path blanked ⇒ no root until update
    const [root] = update(tree, members[1]!);
    for (const m of [...members, m3]) {
      expect(bytesToHex(tree.decryptTreeSecret(m.id, m.sks))).toBe(bytesToHex(root));
    }
  });

  it('remove blanks the path, collects removed keys, and excludes the target', () => {
    const [tree, members] = buildTree(4);
    update(tree, members[0]!);
    const [, removedKeys] = tree.removeId(members[2]!.id);
    expect(removedKeys.length).toBeGreaterThan(0);
    expect(tree.hasRootKey()).toBe(false);
    expect(tree.memberCount()).toBe(3);
    const [root] = update(tree, members[3]!);
    for (const m of [members[0]!, members[1]!, members[3]!]) {
      expect(bytesToHex(tree.decryptTreeSecret(m.id, m.sks))).toBe(bytesToHex(root));
    }
    expect(() => tree.decryptTreeSecret(members[2]!.id, members[2]!.sks)).toThrow(
      'IdentifierNotFound',
    );
  });

  it('grows past capacity (5th member forces a doubling) and still converges', () => {
    const [tree, members] = buildTree(5);
    const [root] = update(tree, members[4]!);
    for (const m of members) {
      expect(bytesToHex(tree.decryptTreeSecret(m.id, m.sks))).toBe(bytesToHex(root));
    }
  });

  it('concurrent updates merge to conflict keys; fresh update resolves', () => {
    // Two replicas built by identical op sequences.
    const [treeA, membersA] = buildTree(4);
    const [treeB, membersB] = buildTree(4);
    const [, pathA] = update(treeA, membersA[0]!);
    const [, pathB] = update(treeB, membersB[3]!);
    // Cross-apply the concurrent PathChanges.
    treeA.applyPath(pathB);
    treeB.applyPath(pathA);
    // Root now has conflicting versions on both replicas.
    expect(treeA.hasRootKey()).toBe(false);
    expect(treeB.hasRootKey()).toBe(false);
    // The A/B Member objects share deterministic initial keys; rotated keys
    // landed in whichever replica's map performed the update — merge them so
    // membersA[i].sks holds member i's full secret set.
    for (let i = 0; i < membersA.length; i++) membersA[i]!.sks.extend(membersB[i]!.sks);
    // A fresh update through the conflicted path resolves it (replica A's member 1).
    const [rootA, freshPath] = update(treeA, membersA[1]!);
    expect(treeA.hasRootKey()).toBe(true);
    for (const m of membersA) {
      expect(bytesToHex(treeA.decryptTreeSecret(m.id, m.sks))).toBe(bytesToHex(rootA));
    }
    // Fork-compromise property: pathB's fork alone cannot read the new root —
    // an adversary holding only member 3's PRE-fork secrets fails to decrypt.
    const preForkSks = new ShareKeyMap();
    const m3Initial = makeMember(3); // same deterministic initial key, nothing else
    preForkSks.insert(m3Initial.leafPk, generateShareSecretKey(testRng('m3')));
    expect(() => treeA.decryptTreeSecret(membersA[3]!.id, preForkSks)).toThrow();
    // Replica B applies the resolving path and converges for the fresh updater's key.
    treeB.applyPath(freshPath);
    expect(treeB.hasRootKey()).toBe(true);
    // Decrypt on replica B: the members' accumulated secrets live in membersA's
    // maps (updates were drawn there; the A/B Member objects share deterministic
    // initial keys by construction, so membersA[i].sks is the superset).
    for (let i = 0; i < membersB.length; i++) {
      expect(bytesToHex(treeB.decryptTreeSecret(membersB[i]!.id, membersA[i]!.sks))).toBe(
        bytesToHex(rootA),
      );
    }
  });

  it('fork-compromise guard: conflict nodes are excluded from resolutions', () => {
    // After a conflict merge, an encrypter treats the conflicted node as blank
    // and encrypts to its resolution — check resolution descends past the root.
    const [treeA, membersA] = buildTree(2);
    const [treeB, membersB] = buildTree(2);
    const [, pA] = update(treeA, membersA[0]!);
    const [, pB] = update(treeB, membersB[1]!);
    treeA.applyPath(pB);
    expect(treeA.hasRootKey()).toBe(false);
    // Member 0 updates through the conflicted root: must encrypt to leaf 1
    // directly (resolution), and member 1 must still decrypt.
    const [root] = update(treeA, membersA[0]!);
    expect(bytesToHex(treeA.decryptTreeSecret(membersA[1]!.id, membersB[1]!.sks))).toBe(
      bytesToHex(root),
    );
  });

  it('stale PathChange (tree grew since) only merges the leaf and blanks the path', () => {
    // Replica C produces an update against the 2-leaf tree...
    const [treeC, membersC] = buildTree(2);
    const [, stalePath] = update(treeC, membersC[0]!);
    // ...while replica A concurrently grew to 4 leaves (path length 1 → 2).
    const [treeA, membersA] = buildTree(2);
    const m2 = makeMember(2);
    treeA.pushLeaf(m2.id, shareNodeKey(m2.leafPk));
    treeA.applyPath(stalePath); // stale: path length no longer matches
    expect(treeA.hasRootKey()).toBe(false);
    // Fresh update still converges for everyone (member 0's rotated leaf key
    // came from the stale path; its secret lives in membersC[0].sks).
    const [root] = update(treeA, m2);
    for (const [id, sks] of [
      [membersC[0]!.id, membersC[0]!.sks],
      [membersA[1]!.id, membersA[1]!.sks],
      [m2.id, m2.sks],
    ] as const) {
      expect(bytesToHex(treeA.decryptTreeSecret(id, sks))).toBe(bytesToHex(root));
    }
  });

  it('concurrent membership changes: removed paths re-blanked, added leaves re-sorted by id', () => {
    const [tree, members] = buildTree(3);
    update(tree, members[0]!);
    // Concurrently: remove member 1; add two members (added at leaves 3, 4).
    const mX = makeMember(7);
    const mY = makeMember(8);
    tree.pushLeaf(mX.id, shareNodeKey(mX.leafPk));
    tree.pushLeaf(mY.id, shareNodeKey(mY.leafPk));
    const [removedIdx] = tree.removeId(members[1]!.id);
    tree.sortLeavesAndBlankPathsForConcurrentMembershipChanges(
      new Set([bytesToHex(mX.id), bytesToHex(mY.id)]),
      [[members[1]!.id, removedIdx]],
    );
    expect(tree.memberCount()).toBe(4);
    expect(tree.hasRootKey()).toBe(false);
    const [root] = update(tree, members[2]!);
    for (const m of [members[0]!, members[2]!, mX, mY]) {
      expect(bytesToHex(tree.decryptTreeSecret(m.id, m.sks))).toBe(bytesToHex(root));
    }
  });
});
