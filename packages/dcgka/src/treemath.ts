/**
 * Byte-faithful port of beekem/src/treemath.rs (OpenMLS-derived, MIT).
 *
 * Convention: this module works in "tree index" space (u32):
 *   leaf i  ⇔ tree index 2i        (even)
 *   inner j ⇔ tree index 2j + 1    (odd)
 * Leaf/inner indices are plain numbers in their own spaces; conversions are explicit.
 */

export const leafToTree = (leaf: number): number => leaf * 2;
export const innerToTree = (inner: number): number => inner * 2 + 1;
export const isLeafTreeIndex = (x: number): boolean => x % 2 === 0;
export const treeToLeaf = (x: number): number => {
  if (!isLeafTreeIndex(x)) throw new Error('not a leaf tree index');
  return x / 2;
};
export const treeToInner = (x: number): number => {
  if (isLeafTreeIndex(x)) throw new Error('not an inner tree index');
  return (x - 1) / 2;
};

function log2(x: number): number {
  if (x === 0) return 0;
  let k = 0;
  while (x >> k > 0) k += 1;
  return k - 1;
}

/** `level(index)` — height of a tree index (0 for leaves). */
export function level(x: number): number {
  if ((x & 0x01) === 0) return 0;
  let k = 0;
  while (((x >> k) & 0x01) === 1) k += 1;
  return k;
}

/** TreeSize newtype (stores the node-count value, always 2^k − 1). */
export class TreeSize {
  private constructor(private v: number) {}

  /** Round `nodes` up to the next 2^k − 1. */
  static new_(nodes: number): TreeSize {
    const k = log2(nodes);
    return new TreeSize((1 << (k + 1)) - 1);
  }

  static fromLeafCount(leafCount: number): TreeSize {
    return TreeSize.new_(leafCount * 2);
  }

  leafCount(): number {
    return Math.floor(this.v / 2) + 1;
  }

  innerNodeCount(): number {
    return Math.floor(this.v / 2);
  }

  u32(): number {
    return this.v;
  }

  /** Grow: size = size * 2 + 1. */
  inc(): void {
    this.v = this.v * 2 + 1;
  }

  gte(other: TreeSize): boolean {
    return this.v >= other.v;
  }

  clone(): TreeSize {
    return new TreeSize(this.v);
  }
}

/** Root tree index for a given size. */
export function root(size: TreeSize): number {
  const s = size.u32();
  if (s <= 0) throw new Error('empty tree');
  return (1 << log2(s)) - 1;
}

/** Left child (tree index) of an inner node (inner-index space). */
export function left(inner: number): number {
  const x = innerToTree(inner);
  const k = level(x);
  if (k <= 0) throw new Error('leaf has no children');
  return x ^ (0x01 << (k - 1));
}

/** Right child (tree index) of an inner node (inner-index space). */
export function right(inner: number): number {
  const x = innerToTree(inner);
  const k = level(x);
  if (k <= 0) throw new Error('leaf has no children');
  return x ^ (0x03 << (k - 1));
}

/** Parent (inner-index space) of a tree index. No bounds check (as upstream). */
export function parent(x: number): number {
  const k = level(x);
  const b = (x >> (k + 1)) & 0x01;
  const index = (x | (1 << k)) ^ (b << (k + 1));
  return treeToInner(index);
}

/** Sibling (tree index) of a tree index. */
export function sibling(x: number): number {
  const p = parent(x);
  const pt = innerToTree(p);
  return x < pt ? right(p) : left(p);
}

/** Direct path (inner-index space) from a tree index to the root, exclusive of the node. */
export function directPath(x: number, size: TreeSize): number[] {
  const r = root(size);
  const d: number[] = [];
  let cur = x;
  while (cur !== r) {
    const p = parent(cur);
    d.push(p);
    cur = innerToTree(p);
  }
  return d;
}

/** Lowest common ancestor (inner-index space) of two leaves (leaf-index space). */
export function lowestCommonAncestor(xLeaf: number, yLeaf: number): number {
  const x = leafToTree(xLeaf);
  const y = leafToTree(yLeaf);
  const lx = level(x) + 1;
  const ly = level(y) + 1;
  if (lx <= ly && x >> ly === y >> ly) return treeToInner(y);
  if (ly <= lx && x >> lx === y >> lx) return treeToInner(x);
  let xn = x;
  let yn = y;
  let k = 0;
  while (xn !== yn) {
    xn >>= 1;
    yn >>= 1;
    k += 1;
  }
  return treeToInner((xn << k) + (1 << (k - 1)) - 1);
}
