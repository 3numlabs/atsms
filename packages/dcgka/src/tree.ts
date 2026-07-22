/**
 * Byte-faithful port of beekem/src/tree.rs — the BeeKEM ratchet tree.
 *
 * MemberIds are opaque 32-byte identifiers ordered lexicographically (in the
 * ATSMS profile they are device fingerprints — dgm.md §2/Spike B §3; upstream
 * uses ed25519 verifying keys, also 32 bytes, so vectors interoperate).
 *
 * All derivations below the PcsKey seam are the keyhive BLAKE3 constructions
 * (keyhive.ts) — beekem-core §3 (KDF split, DECIDED 2026-07-22).
 */

import { bytesToHex, compareBytes } from './bytes.js';
import { encryptSecret, type EncryptedSecret } from './encrypted.js';
import {
  generateShareSecretKey,
  ratchetForward,
  ratchetNForward,
  shareKeyOf,
  type Csprng,
} from './keyhive.js';
import {
  nodeKeyKeys,
  nodeKeyMerge,
  shareNodeKey,
  type NodeKey,
  type ShareKeyMap,
} from './keys.js';
import { SecretStore } from './secretstore.js';
import * as tm from './treemath.js';

export interface LeafNode {
  id: Uint8Array; // MemberId (32 bytes)
  pk: NodeKey;
}

/** Rust `PathChange` (wire shape in wire-format §4.1). */
export interface PathChange {
  leafId: Uint8Array;
  leafIdx: number;
  leafPk: NodeKey;
  /** (inner node index, new inner node) pairs, leaf-parent → root. */
  path: Array<[number, SecretStore]>;
  removedKeys: Uint8Array[];
}

export class BeeKem {
  readonly docId: Uint8Array;
  private nextLeafIdx = 0;
  private leaves: Array<LeafNode | null> = [];
  private innerNodes: Array<SecretStore | null> = [];
  private treeSize: tm.TreeSize;
  private idToLeafIdx = new Map<string, number>();
  /** Leaf index of the last path encrypter, or null when there is no root key. */
  currentSecretEncrypterLeafIdx: number | null = null;

  constructor(docId: Uint8Array, initialMemberId: Uint8Array, initialMemberPk: Uint8Array) {
    this.docId = docId;
    this.treeSize = tm.TreeSize.fromLeafCount(1);
    this.growTreeToSize();
    this.pushLeaf(initialMemberId, shareNodeKey(initialMemberPk));
  }

  containsId(id: Uint8Array): boolean {
    return this.idToLeafIdx.has(bytesToHex(id));
  }

  memberCount(): number {
    return this.idToLeafIdx.size;
  }

  leafIndexForId(id: Uint8Array): number {
    const idx = this.idToLeafIdx.get(bytesToHex(id));
    if (idx === undefined) throw new Error('IdentifierNotFound');
    return idx;
  }

  nodeKeyForId(id: Uint8Array): NodeKey {
    return this.nodeKeyForIndex(tm.leafToTree(this.leafIndexForId(id)));
  }

  /** Rust `push_leaf` — next free leaf on the right; blanks its path. Returns the leaf index. */
  pushLeaf(id: Uint8Array, pk: NodeKey): number {
    this.maybeGrowTree(this.nextLeafIdx);
    const lIdx = this.nextLeafIdx;
    this.nextLeafIdx += 1;
    this.insertLeafAt(lIdx, id, pk);
    this.idToLeafIdx.set(bytesToHex(id), lIdx);
    this.blankPath(tm.parent(tm.leafToTree(lIdx)));
    return lIdx;
  }

  /** Rust `remove_id` — blanks leaf + path; trims right-edge tombstones. */
  removeId(id: Uint8Array): [number, Uint8Array[]] {
    if (this.memberCount() === 1) throw new Error('RemoveLastMember');
    const lIdx = this.leafIndexForId(id);
    const removedKeys: Uint8Array[] = [];
    for (const idx of tm.directPath(tm.leafToTree(lIdx), this.treeSize)) {
      const store = this.innerNode(idx);
      if (store !== null) removedKeys.push(...nodeKeyKeys(store.nodeKey()));
    }
    this.blankLeafAndPath(lIdx);
    this.idToLeafIdx.delete(bytesToHex(id));
    while (this.nextLeafIdx > 0 && this.leaf(this.nextLeafIdx - 1) === null) {
      this.blankPath(tm.parent(tm.leafToTree(this.nextLeafIdx - 1)));
      this.nextLeafIdx -= 1;
    }
    return [lIdx, removedKeys];
  }

  /** Rust `sort_leaves_and_blank_paths_for_concurrent_membership_changes`. */
  sortLeavesAndBlankPathsForConcurrentMembershipChanges(
    addedIds: Set<string>,
    removedIds: Array<[Uint8Array, number]>,
  ): void {
    const added = new Set(addedIds);
    const leavesToSort: LeafNode[] = [];
    for (const [id, idx] of removedIds) {
      added.delete(bytesToHex(id));
      this.blankLeafAndPath(idx);
    }
    while (added.size > 0 && this.nextLeafIdx > 0) {
      const leafIdx = this.nextLeafIdx - 1;
      const nextLeaf = this.leaf(leafIdx);
      if (nextLeaf !== null) {
        added.delete(bytesToHex(nextLeaf.id));
        leavesToSort.push(nextLeaf);
      }
      this.blankLeafAndPath(leafIdx);
      this.nextLeafIdx = leafIdx;
    }
    leavesToSort.sort((a, b) => compareBytes(a.id, b.id));
    for (const leaf of leavesToSort) {
      this.idToLeafIdx.delete(bytesToHex(leaf.id)); // re-push below reassigns
      this.pushLeaf(leaf.id, leaf.pk);
    }
  }

  blankLeafAndPath(idx: number): void {
    this.leaves[idx] = null;
    this.blankPath(tm.parent(tm.leafToTree(idx)));
  }

  /** Rust `has_root_key`. */
  hasRootKey(): boolean {
    const rootIdx = tm.root(this.treeSize);
    if (tm.isLeafTreeIndex(rootIdx)) throw new Error('BeeKEM root must be an inner node');
    const r = this.innerNode(tm.treeToInner(rootIdx));
    return r !== null && !r.hasConflict();
  }

  /**
   * Rust `decrypt_tree_secret` — derive the current root secret (PcsKey input)
   * for `ownerId`, learning path secrets into `ownerSks` along the way.
   */
  decryptTreeSecret(ownerId: Uint8Array, ownerSks: ShareKeyMap): Uint8Array {
    const leafIdx = this.leafIndexForId(ownerId);
    if (!this.hasRootKey()) throw new Error('NoRootKey');
    const leaf = this.leaf(leafIdx);
    if (leaf === null) throw new Error('Leaf should not be blank');

    if (leafIdx === this.currentSecretEncrypterLeafIdx) {
      if (leaf.pk.kind !== 'share') throw new Error('ShareKeyNotFound');
      const secret = ownerSks.get(leaf.pk.pk);
      if (secret === undefined) throw new Error('ShareKeyNotFound');
      return ratchetNForward(secret, tm.directPath(tm.leafToTree(leafIdx), this.treeSize).length);
    }
    if (this.currentSecretEncrypterLeafIdx === null) {
      throw new Error('A tree with a root key should have a current encrypter');
    }
    const lcaWithEncrypter = tm.lowestCommonAncestor(leafIdx, this.currentSecretEncrypterLeafIdx);

    let childIdx = tm.leafToTree(leafIdx);
    const seenIdxs: number[] = [childIdx];
    let maybeLastSecretDecrypted: Uint8Array | null = null;
    let childNodeKey: NodeKey = leaf.pk;
    let parentIdx = tm.innerToTree(tm.parent(childIdx));
    while (!this.isRoot(childIdx)) {
      while (this.shouldSkipForResolution(parentIdx)) {
        childIdx = parentIdx;
        parentIdx = tm.innerToTree(tm.parent(childIdx));
      }
      maybeLastSecretDecrypted = this.maybeDecryptParentKey(childIdx, childNodeKey, seenIdxs, ownerSks);
      if (maybeLastSecretDecrypted === null) {
        throw new Error('Non-blank, non-conflict parent should have a secret we can decrypt');
      }
      if (parentIdx === tm.innerToTree(lcaWithEncrypter)) {
        return ratchetNForward(
          maybeLastSecretDecrypted,
          tm.directPath(parentIdx, this.treeSize).length,
        );
      }
      seenIdxs.push(parentIdx);
      childIdx = parentIdx;
      childNodeKey = this.nodeKeyForIndex(childIdx);
      parentIdx = tm.innerToTree(tm.parent(childIdx));
    }
    if (maybeLastSecretDecrypted === null) throw new Error('NoRootKey');
    return maybeLastSecretDecrypted;
  }

  /**
   * Rust `encrypt_path` — rotate `id`'s leaf to `pk` and encrypt a fresh secret
   * at every ancestor. Returns [rootSecret (= PcsKey input), PathChange].
   * `sks` must already contain sk for `pk`; learned parent secrets are added.
   */
  encryptPath(
    id: Uint8Array,
    pk: Uint8Array,
    sks: ShareKeyMap,
    csprng: Csprng,
  ): [Uint8Array, PathChange] {
    const leafIdx = this.leafIndexForId(id);
    const newPath: PathChange = {
      leafId: id,
      leafIdx,
      leafPk: shareNodeKey(pk),
      path: [],
      removedKeys: nodeKeyKeys(this.nodeKeyForId(id)),
    };
    this.insertLeafAt(leafIdx, id, shareNodeKey(pk));
    let childIdx = tm.leafToTree(leafIdx);
    let childPk = pk;
    const sk0 = sks.get(pk);
    if (sk0 === undefined) throw new Error('SecretKeyNotFound');
    let childSk = sk0;
    let parentIdx = tm.parent(childIdx);
    while (!this.isRoot(childIdx)) {
      const store = this.innerNode(parentIdx);
      if (store !== null) newPath.removedKeys.push(...nodeKeyKeys(store.nodeKey()));
      const newParentSk = ratchetForward(childSk);
      const newParentPk = shareKeyOf(newParentSk);
      sks.insert(newParentPk, newParentSk);
      this.encryptKeyForParent(childIdx, childPk, childSk, newParentPk, newParentSk, csprng);
      const inserted = this.innerNode(parentIdx);
      if (inserted === null) throw new Error('Parent node should not be null after encryption');
      newPath.path.push([parentIdx, inserted.clone()]);
      childIdx = tm.innerToTree(parentIdx);
      childPk = newParentPk;
      childSk = newParentSk;
      parentIdx = tm.parent(childIdx);
    }
    this.currentSecretEncrypterLeafIdx = leafIdx;
    return [childSk, newPath];
  }

  /** Rust `apply_path` — merge a (possibly concurrent) PathChange into the tree. */
  applyPath(newPath: PathChange): void {
    if (!this.idToLeafIdx.has(bytesToHex(newPath.leafId))) return;
    const leafIdx = this.leafIndexForId(newPath.leafId);
    if (!this.isValidPath(newPath)) {
      const leaf = this.leaf(leafIdx);
      if (leaf === null) throw new Error('Leaf for present ID should not be null');
      const newNodeKey = nodeKeyMerge(leaf.pk, newPath.leafPk, newPath.removedKeys);
      this.insertLeafAt(leafIdx, newPath.leafId, newNodeKey);
      this.blankPath(tm.parent(tm.leafToTree(leafIdx)));
      return;
    }

    const oldLeaf = this.leaf(leafIdx);
    if (oldLeaf === null) throw new Error('Leaf for present ID should not be null');
    this.insertLeafAt(
      leafIdx,
      newPath.leafId,
      nodeKeyMerge(oldLeaf.pk, newPath.leafPk, newPath.removedKeys),
    );

    const removedKeysSet = new Set(newPath.removedKeys.map(bytesToHex));
    for (const [idx, node] of newPath.path) {
      const current = this.innerNode(idx);
      if (current !== null) {
        current.merge(node, removedKeysSet);
      } else {
        this.insertInnerNodeAt(idx, node.clone());
      }
    }

    this.currentSecretEncrypterLeafIdx = this.hasRootKey() ? leafIdx : null;
  }

  // ── internals ────────────────────────────────────────────────────────────

  private maybeDecryptParentKey(
    childIdx: number,
    childNodeKey: NodeKey,
    seenIdxs: number[],
    childSks: ShareKeyMap,
  ): Uint8Array | null {
    const parentIdx = tm.parent(childIdx);
    const parent = this.innerNode(parentIdx);
    if (parent === null) return null;
    const nk = parent.nodeKey();
    if (nk.kind === 'conflict') return null;
    const parentPk = nk.pk;
    const cached = childSks.get(parentPk);
    if (cached !== undefined) return cached;
    const secret = parent.decryptSecret(childNodeKey, childSks, seenIdxs);
    childSks.insert(parentPk, secret);
    return secret;
  }

  private encryptKeyForParent(
    childIdx: number,
    childPk: Uint8Array,
    childSk: Uint8Array,
    newParentPk: Uint8Array,
    newParentSk: Uint8Array,
    csprng: Csprng,
  ): void {
    const parentIdx = tm.parent(childIdx);
    const secretStore = this.encryptNewSecretStoreForParent(
      childIdx,
      childPk,
      childSk,
      newParentPk,
      newParentSk,
      csprng,
    );
    this.insertInnerNodeAt(parentIdx, secretStore);
  }

  private encryptNewSecretStoreForParent(
    childIdx: number,
    childPk: Uint8Array,
    childSk: Uint8Array,
    newParentPk: Uint8Array,
    newParentSk: Uint8Array,
    csprng: Csprng,
  ): SecretStore {
    const siblingIdx = tm.sibling(childIdx);
    const secretMap = new Map<number, EncryptedSecret>();
    const siblingResolution: number[] = [];
    this.appendResolution(siblingIdx, siblingResolution);
    if (siblingResolution.length === 0) {
      // Blank sibling subtree: throwaway DH pair just for this encryption.
      const pairedSk = generateShareSecretKey(csprng);
      const pairedPk = shareKeyOf(pairedSk);
      const encryptedSk = encryptSecret(this.docId, newParentSk, childSk, pairedPk);
      secretMap.set(childIdx, encryptedSk);
    } else {
      let usedPairedSibling = false;
      for (const idx of siblingResolution) {
        const nk = this.nodeKeyForIndex(idx);
        if (nk.kind !== 'share') {
          throw new Error('Sibling resolution nodes should have exactly one ShareKey');
        }
        const encryptedSk = encryptSecret(this.docId, newParentSk, childSk, nk.pk);
        if (!usedPairedSibling) {
          secretMap.set(childIdx, encryptedSk);
          usedPairedSibling = true;
        }
        secretMap.set(idx, encryptedSk);
      }
    }
    return SecretStore.new_(newParentPk, childPk, secretMap);
  }

  private nodeKeyForIndex(idx: number): NodeKey {
    if (tm.isLeafTreeIndex(idx)) {
      const leaf = this.leaf(tm.treeToLeaf(idx));
      if (leaf === null) throw new Error('ShareKeyNotFound');
      return leaf.pk;
    }
    const inner = this.innerNode(tm.treeToInner(idx));
    if (inner === null) throw new Error('ShareKeyNotFound');
    return inner.nodeKey();
  }

  private leaf(idx: number): LeafNode | null {
    if (idx < 0 || idx >= this.leaves.length) throw new Error('Leaf index out of bounds');
    return this.leaves[idx]!;
  }

  private innerNode(idx: number): SecretStore | null {
    if (idx < 0 || idx >= this.innerNodes.length) throw new Error('Inner node index out of bounds');
    return this.innerNodes[idx]!;
  }

  private insertLeafAt(idx: number, id: Uint8Array, pk: NodeKey): void {
    this.leaves[idx] = { id, pk };
  }

  private insertInnerNodeAt(idx: number, store: SecretStore): void {
    this.innerNodes[idx] = store;
  }

  private isBlank(idx: number): boolean {
    return tm.isLeafTreeIndex(idx)
      ? this.leaf(tm.treeToLeaf(idx)) === null
      : this.innerNode(tm.treeToInner(idx)) === null;
  }

  private shouldSkipForResolution(idx: number): boolean {
    if (tm.isLeafTreeIndex(idx)) return this.isBlank(idx);
    const n = this.innerNode(tm.treeToInner(idx));
    return n === null || n.hasConflict();
  }

  private blankPath(innerIdx: number): void {
    let idx = innerIdx;
    while (!this.isRoot(tm.innerToTree(idx))) {
      this.blankInnerNode(idx);
      idx = tm.parent(tm.innerToTree(idx));
    }
    this.blankInnerNode(idx);
    this.currentSecretEncrypterLeafIdx = null;
  }

  private blankInnerNode(idx: number): void {
    this.innerNodes[idx] = null;
  }

  private isValidPath(newPath: PathChange): boolean {
    const leafIdx = this.leafIndexForId(newPath.leafId);
    return (
      newPath.path.length === tm.directPath(tm.leafToTree(newPath.leafIdx), this.treeSize).length &&
      leafIdx === newPath.leafIdx
    );
  }

  private maybeGrowTree(newCount: number): void {
    if (this.treeSize.gte(tm.TreeSize.fromLeafCount(newCount))) return;
    this.treeSize.inc();
    this.growTreeToSize();
  }

  private growTreeToSize(): void {
    while (this.leaves.length < this.treeSize.leafCount()) this.leaves.push(null);
    while (this.innerNodes.length < this.treeSize.innerNodeCount()) this.innerNodes.push(null);
  }

  private isRoot(idx: number): boolean {
    return idx === tm.root(this.treeSize);
  }

  /** Highest non-blank, non-conflict descendants of a node. */
  private appendResolution(idx: number, acc: number[]): void {
    if (this.shouldSkipForResolution(idx)) {
      if (!tm.isLeafTreeIndex(idx)) {
        const inner = tm.treeToInner(idx);
        this.appendResolution(tm.left(inner), acc);
        this.appendResolution(tm.right(inner), acc);
      }
    } else {
      acc.push(idx);
    }
  }
}
