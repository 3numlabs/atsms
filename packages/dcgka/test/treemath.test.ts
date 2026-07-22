import { describe, expect, it } from 'vitest';
import * as tm from '../src/treemath.js';

describe('treemath (ports of the Rust unit tests)', () => {
  it('tree_size', () => {
    expect(tm.TreeSize.new_(1).u32()).toBe(1);
    expect(tm.TreeSize.new_(3).u32()).toBe(3);
    expect(tm.TreeSize.new_(5).u32()).toBe(7);
    expect(tm.TreeSize.new_(7).u32()).toBe(7);
    expect(tm.TreeSize.new_(9).u32()).toBe(15);
    expect(tm.TreeSize.new_(11).u32()).toBe(15);
    expect(tm.TreeSize.new_(13).u32()).toBe(15);
    expect(tm.TreeSize.new_(15).u32()).toBe(15);
    expect(tm.TreeSize.new_(17).u32()).toBe(31);
  });

  it('node in tree', () => {
    const cases: Array<[number, number]> = [
      [0, 3],
      [1, 3],
      [2, 5],
      [5, 7],
      [2, 11],
    ];
    for (const [idx, nodes] of cases) {
      expect(idx < tm.TreeSize.new_(nodes).u32()).toBe(true);
    }
    const not: Array<[number, number]> = [
      [3, 1],
      [13, 7],
    ];
    for (const [idx, nodes] of not) {
      expect(idx < tm.TreeSize.new_(nodes).u32()).toBe(false);
    }
  });

  it('parent/left/right/sibling agree on a size-7 tree', () => {
    // Tree indices:      3
    //                 1     5
    //                0 2   4 6
    expect(tm.root(tm.TreeSize.new_(7))).toBe(3);
    expect(tm.parent(0)).toBe(tm.treeToInner(1));
    expect(tm.parent(2)).toBe(tm.treeToInner(1));
    expect(tm.parent(1)).toBe(tm.treeToInner(3));
    expect(tm.parent(4)).toBe(tm.treeToInner(5));
    expect(tm.parent(5)).toBe(tm.treeToInner(3));
    expect(tm.left(tm.treeToInner(3))).toBe(1);
    expect(tm.right(tm.treeToInner(3))).toBe(5);
    expect(tm.left(tm.treeToInner(1))).toBe(0);
    expect(tm.right(tm.treeToInner(1))).toBe(2);
    expect(tm.sibling(0)).toBe(2);
    expect(tm.sibling(2)).toBe(0);
    expect(tm.sibling(1)).toBe(5);
    expect(tm.sibling(4)).toBe(6);
  });

  it('directPath and lowestCommonAncestor', () => {
    const size = tm.TreeSize.new_(7); // 4 leaves
    expect(tm.directPath(0, size)).toEqual([tm.treeToInner(1), tm.treeToInner(3)]);
    expect(tm.directPath(6, size)).toEqual([tm.treeToInner(5), tm.treeToInner(3)]);
    expect(tm.directPath(3, size)).toEqual([]);
    // leaves 0 and 1 (tree 0 and 2) meet at inner 1; leaves 0 and 3 at the root
    expect(tm.innerToTree(tm.lowestCommonAncestor(0, 1))).toBe(1);
    expect(tm.innerToTree(tm.lowestCommonAncestor(0, 3))).toBe(3);
    expect(tm.innerToTree(tm.lowestCommonAncestor(2, 3))).toBe(5);
  });
});
