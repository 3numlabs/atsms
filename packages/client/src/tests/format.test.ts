/**
 * v2 message format (src/lib/format) — codec determinism, derived IDs, and the
 * §5.2 render policy (docs/message-format.md).
 */

import { bytesToHex } from "@atsms/dcgka";
import { describe, expect, test } from "bun:test";

import {
  cborDecode,
  cborEncode,
  type CborValue,
  conversationConvoId,
  convoIdToHex,
  createContent,
  decodeContent,
  deriveMessageId,
  encodeContent,
  EXT_RECIPIENTS,
  groupIdOfConvoId,
  inlineFilePart,
  KIND_REACTION,
  oneShotConvoIdV2,
  reactionPart,
  recipientsExtension,
  renderModel,
  textOf,
  textPart,
} from "../lib/format/index.js";

const salt = new Uint8Array(16).fill(7);
const groupIdHex = "ab".repeat(32);
const convoId = conversationConvoId(groupIdHex);

describe("deterministic CBOR with maps", () => {
  test("map encoding is insertion-order independent", () => {
    const a = new Map<string, CborValue>([
      ["b", 2],
      ["a", 1],
    ]);
    const b = new Map<string, CborValue>([
      ["a", 1],
      ["b", 2],
    ]);
    expect(bytesToHex(cborEncode(a))).toBe(bytesToHex(cborEncode(b)));
  });

  test("integer keys sort before longer-encoded keys by encoded bytes", () => {
    const m = new Map<number | string, CborValue>([
      ["z", 1],
      [3, 2],
    ]);
    const encoded = cborEncode(m);
    const decoded = cborDecode(encoded) as Map<number | string, CborValue>;
    expect([...decoded.keys()]).toEqual([3, "z"]);
  });

  test("out-of-order map keys are rejected on decode", () => {
    // {"b": 1, "a": 2} in that (wrong) order: a2 61 62 01 61 61 02
    const bad = Uint8Array.of(0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02);
    expect(() => cborDecode(bad)).toThrow("out of deterministic order");
  });

  test("duplicate map keys are rejected", () => {
    const bad = Uint8Array.of(0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02);
    expect(() => cborDecode(bad)).toThrow();
  });

  test("non-minimal integers are rejected", () => {
    expect(() => cborDecode(Uint8Array.of(0x18, 0x17))).toThrow("non-minimal");
  });

  test("floats and tags are rejected", () => {
    expect(() => cborEncode(1.5 as unknown as CborValue)).toThrow();
    expect(() => cborDecode(Uint8Array.of(0xc0, 0x60))).toThrow("tags rejected");
  });
});

describe("content codec", () => {
  test("full-featured content round-trips exactly", () => {
    const target = new Uint8Array(32).fill(1);
    const content = createContent({
      convoId,
      salt,
      createdAt: 1753920000000,
      inReplyTo: target,
      topicId: new Uint8Array(32).fill(2),
      expires: { relative: true, time: 3600 },
      fallback: "a message",
      extensions: new Map([[EXT_RECIPIENTS, ["did:web:a", "did:web:b"]]]),
      body: [textPart("hello", [{ byteStart: 0, byteEnd: 5, feature: { type: "tag", tag: "hi" } }])],
    });
    const bytes = encodeContent(content);
    const decoded = decodeContent(bytes);
    expect(bytesToHex(encodeContent(decoded))).toBe(bytesToHex(bytes));
    expect(decoded.createdAt).toBe(1753920000000);
    expect(decoded.inReplyTo).toEqual(target);
    expect(decoded.expires).toEqual({ relative: true, time: 3600 });
    expect(recipientsExtension(decoded, EXT_RECIPIENTS)).toEqual(["did:web:a", "did:web:b"]);
    expect(textOf(decoded)).toBe("hello");
  });

  test("encoding is stable (golden vector)", () => {
    const content = createContent({ convoId, salt, createdAt: 1753920000000, body: [textPart("hi")] });
    // Locks the wire layout: any codec change that alters bytes (and therefore
    // every derived message ID) must be deliberate and update this vector.
    expect(bytesToHex(encodeContent(content))).toBe(
      "8c0250070707070707070707070707070707075821" +
        "02" +
        "ab".repeat(32) +
        "1b000001985dc75000f6f6f6f6f460a08182018200a16474657874626869",
    );
  });

  test("tombstone: null body with replaces", () => {
    const original = new Uint8Array(32).fill(9);
    const content = createContent({ convoId, salt, replaces: original, body: null });
    const decoded = decodeContent(encodeContent(content));
    expect(decoded.body).toBeNull();
    expect(renderModel(decoded).tombstone).toBe(true);
  });

  test("wrong version and malformed salt are rejected", () => {
    const bytes = encodeContent(createContent({ convoId, salt, body: [textPart("x")] }));
    const wrongVersion = new Uint8Array(bytes);
    wrongVersion[1] = 3; // top-level [v, ...] — bump v from 2 to 3
    expect(() => decodeContent(wrongVersion)).toThrow("unsupported version");
    expect(() => encodeContent(createContent({ convoId, salt: new Uint8Array(8), body: null }))).toThrow("salt");
  });
});

describe("derived IDs", () => {
  test("message ID binds sender, conversation, content, and salt", () => {
    const content = createContent({ convoId, salt, createdAt: 1, body: [textPart("hi")] });
    const bytes = encodeContent(content);
    const id = deriveMessageId("did:web:alice", content, bytes);
    expect(id.length).toBe(32);
    expect(id[0]).toBe(0x01); // SHA-256 marker

    const otherSender = deriveMessageId("did:web:bob", content, bytes);
    expect(bytesToHex(otherSender)).not.toBe(bytesToHex(id));

    const otherContent = createContent({ convoId, salt, createdAt: 1, body: [textPart("hi!")] });
    const otherBytes = encodeContent(otherContent);
    expect(bytesToHex(deriveMessageId("did:web:alice", otherContent, otherBytes))).not.toBe(bytesToHex(id));

    // Same inputs → same ID (receiver recomputes what the sender derived).
    expect(bytesToHex(deriveMessageId("did:web:alice", content, bytes))).toBe(bytesToHex(id));
  });

  test("one-shot convoId is order/dup independent and context-tagged", () => {
    const a = oneShotConvoIdV2(["did:web:b", "did:web:a"]);
    const b = oneShotConvoIdV2(["did:web:a", "did:web:b", "did:web:a"]);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
    expect(a.length).toBe(33);
    expect(a[0]).toBe(0x01);
  });

  test("conversation convoId wraps and unwraps the GroupID", () => {
    expect(convoId.length).toBe(33);
    expect(convoId[0]).toBe(0x02);
    expect(groupIdOfConvoId(convoId)).toBe(groupIdHex);
    expect(groupIdOfConvoId(oneShotConvoIdV2(["did:web:a"]))).toBeNull();
    expect(convoIdToHex(convoId)).toBe("02" + groupIdHex);
  });

  test("the two convoId spaces are structurally disjoint", () => {
    const oneShot = oneShotConvoIdV2(["did:web:a", "did:web:b"]);
    expect(oneShot[0]).not.toBe(convoId[0]);
  });
});

describe("render policy (§5.2)", () => {
  test("known render part → renders, unknown siblings ignored", () => {
    const decoded = decodeContent(
      encodeContent(
        createContent({
          convoId,
          salt,
          fallback: "fallback",
          body: [textPart("hello"), { kind: 4242, body: new Map([["x", 1]]) }],
        }),
      ),
    );
    const model = renderModel(decoded);
    expect(model.renderParts.length).toBe(1);
    expect(model.degraded).toBeNull();
  });

  test("only unknown kinds + fallback → fallback text", () => {
    const decoded = decodeContent(
      encodeContent(
        createContent({ convoId, salt, fallback: "sent you a thing", body: [{ kind: 4242, body: new Map() }] }),
      ),
    );
    const model = renderModel(decoded);
    expect(model.degraded).toBe("fallback");
    expect(textOf(decoded)).toBe("sent you a thing");
  });

  test("only unknown kinds, no fallback → hidden (never raw structure)", () => {
    const decoded = decodeContent(
      encodeContent(createContent({ convoId, salt, body: [{ kind: 4242, body: new Map() }] })),
    );
    expect(renderModel(decoded).degraded).toBe("hidden");
    expect(textOf(decoded)).toBeNull();
  });

  test("pure apply message (a reaction) is not degraded and not rendered", () => {
    const decoded = decodeContent(
      encodeContent(
        createContent({ convoId, salt, inReplyTo: new Uint8Array(32).fill(3), body: [reactionPart("👍")] }),
      ),
    );
    const model = renderModel(decoded);
    expect(model.renderParts.length).toBe(0);
    expect(model.applyParts[0]?.kind).toBe(KIND_REACTION);
    expect(model.degraded).toBeNull();
  });

  test("inline file summarizes by filename", () => {
    const decoded = decodeContent(
      encodeContent(
        createContent({ convoId, salt, body: [inlineFilePart(new Uint8Array(3), "image/png", "cat.png")] }),
      ),
    );
    expect(textOf(decoded)).toBe("cat.png");
  });
});
