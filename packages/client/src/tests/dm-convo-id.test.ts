/**
 * Tests for deterministic DM conversation ID generation
 */

import { describe, expect, test } from "bun:test";

import { generateDMConvoId, isDMConvoId } from "../lib/messages";

describe("generateDMConvoId", () => {
  test("produces same ID regardless of DID order", async () => {
    const did1 = "did:plc:alice123";
    const did2 = "did:plc:bob456";

    const id1 = await generateDMConvoId(did1, did2);
    const id2 = await generateDMConvoId(did2, did1);

    expect(id1).toBe(id2);
  });

  test("starts with dm_ prefix", async () => {
    const id = await generateDMConvoId("did:plc:aaa", "did:plc:bbb");
    expect(id.startsWith("dm_")).toBe(true);
  });

  test("has consistent length (dm_ + 16 hex chars)", async () => {
    const id = await generateDMConvoId("did:plc:aaa", "did:plc:bbb");
    expect(id.length).toBe(3 + 16); // "dm_" + 16 hex chars
  });

  test("produces different IDs for different participant pairs", async () => {
    const id1 = await generateDMConvoId("did:plc:alice", "did:plc:bob");
    const id2 = await generateDMConvoId("did:plc:alice", "did:plc:carol");
    const id3 = await generateDMConvoId("did:plc:bob", "did:plc:carol");

    expect(id1).not.toBe(id2);
    expect(id1).not.toBe(id3);
    expect(id2).not.toBe(id3);
  });

  test("is deterministic across multiple calls", async () => {
    const did1 = "did:plc:xyz789";
    const did2 = "did:plc:abc123";

    const results = await Promise.all([
      generateDMConvoId(did1, did2),
      generateDMConvoId(did1, did2),
      generateDMConvoId(did2, did1),
    ]);

    expect(results[0]).toBe(results[1]);
    expect(results[0]).toBe(results[2]);
  });

  test("only contains valid hex characters after prefix", async () => {
    const id = await generateDMConvoId("did:plc:test1", "did:plc:test2");
    const hexPart = id.substring(3);
    expect(hexPart).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe("isDMConvoId", () => {
  test("returns true for dm_ prefixed IDs", () => {
    expect(isDMConvoId("dm_a1b2c3d4e5f6g7h8")).toBe(true);
    expect(isDMConvoId("dm_0000000000000000")).toBe(true);
  });

  test("returns false for non-dm IDs", () => {
    expect(isDMConvoId("abc123def456")).toBe(false);
    expect(isDMConvoId("DM_uppercase")).toBe(false);
    expect(isDMConvoId("")).toBe(false);
  });
});
