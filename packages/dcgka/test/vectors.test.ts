/**
 * Frozen test-vector suite (wire-format.md §9): the normative byte-level
 * regression gate. Each builder computes vectors deterministically from the
 * implementation; the vectors are frozen to JSON under `test-vectors/` and
 * this test asserts the implementation still reproduces them byte-for-byte.
 *
 * Bootstrapping: if a frozen file is absent it is WRITTEN (first run), then the
 * fresh value trivially equals it. To intentionally regenerate after a
 * deliberate wire change, delete the file and re-run (then review the diff).
 *
 * Covers the `kdf/` and `frames/` directories of §9; `beekem/` is
 * `beekem-oracle.json` (test/oracle.test.ts); `envelopes/` lands with Phase 3.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import {
  deriveFromBytes,
  deriveSymmetricKey,
  ratchetForward,
  ratchetNForward,
  shareKeyOf,
  sivNew,
  tryEncrypt,
} from '../src/keyhive.js';
import {
  chainMsgKey,
  chainNext,
  chainNonce,
  chainSeed,
  expand,
  LABEL_CHAIN,
  rootCommit,
} from '../src/kdf.js';
import { concatBytes } from '../src/bytes.js';
import { decodeExt, encodeExt } from '../src/ext.js';
import { encodeFrameBody, messageIdOf, parseFrame, signFrame, generateSigningKeypair } from '../src/frames.js';
import { encodeMembership, ZERO32, type Membership } from '../src/ids.js';
import { buildInboxRecord, buildPrekeyRecord, prekeyBundleSigInput } from '../src/records.js';
import { p256 } from '@noble/curves/p256';
import { blake3 } from '@noble/hashes/blake3';
import {
  CONTENT_FRAME,
  SEAL_ASYM_INFO,
  envKeySym,
  envelopeId,
  hintTag,
  openAsym,
  openSym,
  padToBucket,
  sealAsymTo,
  sealSymTo,
} from '../src/envelope.js';
import { sealBase } from '../src/hpke.js';
import { x25519 } from '@noble/curves/ed25519';

const H = bytesToHex;
const fill = (n: number, b: number) => new Uint8Array(n).fill(b);

// ── kdf vectors ──────────────────────────────────────────────────────────────

function buildKdfVectors(): unknown {
  const ck = fill(32, 0x11);
  const pcsKey = fill(32, 0x22);
  const sender: Membership = {
    device: { did: 'did:web:001.fid.is', fingerprint: fill(32, 0x33) },
    admittedBy: fill(32, 0x44),
  };
  const encSender = encodeMembership(sender);
  const skA = fill(32, 0x55);
  const skB = fill(32, 0x66);

  return {
    description:
      'KDF vectors (wire-format §9). keyhive_blake3: tree-layer primitives (BLAKE3, ' +
      'derive_key context "/keyhive/"). hkdf_profile: HKDF-SHA256 above the PcsKey seam ' +
      '(atsms-beekem:v1:* labels) + rootCommit. Byte-frozen; delete this file to regenerate.',
    keyhive_blake3: {
      deriveFromBytes_zero32: { input: H(fill(32, 0)), output: H(deriveFromBytes(fill(32, 0))) },
      ratchetForward: { input: H(fill(32, 0x44)), output: H(ratchetForward(fill(32, 0x44))) },
      ratchetNForward_3: { input: H(ck), n: 3, output: H(ratchetNForward(ck, 3)) },
      shareKeyOf: { sk: H(skA), pk: H(shareKeyOf(skA)) },
      deriveSymmetricKey: {
        sk: H(skA),
        pk: H(shareKeyOf(skB)),
        output: H(deriveSymmetricKey(skA, shareKeyOf(skB))),
      },
      sivNew: {
        key: H(fill(32, 0x77)),
        plaintext: H(fill(16, 0x88)),
        docId: H(fill(32, 0x99)),
        output: H(sivNew(fill(32, 0x77), fill(16, 0x88), fill(32, 0x99))),
      },
      tryEncrypt: (() => {
        const key = fill(32, 0xaa);
        const nonce = sivNew(key, fill(8, 0xbb), fill(32, 0xcc));
        return {
          key: H(key),
          nonce: H(nonce),
          plaintext: H(fill(8, 0xbb)),
          ciphertext: H(tryEncrypt(key, nonce, fill(8, 0xbb))),
        };
      })(),
    },
    hkdf_profile: {
      expand_chain_label: {
        ikm: H(pcsKey),
        info: H(LABEL_CHAIN),
        output: H(expand(pcsKey, LABEL_CHAIN)),
      },
      chainSeed: {
        pcsKey: H(pcsKey),
        encodedSenderMembership: H(encSender),
        output: H(chainSeed(pcsKey, encSender)),
      },
      chainMsgKey: { ck: H(ck), output: H(chainMsgKey(ck)) },
      chainNonce12: { ck: H(ck), output: H(chainNonce(ck)) },
      chainNext: { ck: H(ck), output: H(chainNext(ck)) },
      rootCommit: { pcsKey: H(pcsKey), output: H(rootCommit(pcsKey)) },
    },
  };
}

// ── frames vectors ───────────────────────────────────────────────────────────

const SIGN_SEED = fill(32, 0x01);
const membership = (did: string, fp: number, admittedBy: Uint8Array): Membership => ({
  device: { did, fingerprint: fill(32, fp) },
  admittedBy,
});

function frameVector(name: string, body: Parameters<typeof encodeFrameBody>[0]): unknown {
  const bodyBytes = encodeFrameBody(body);
  const raw = signFrame(bodyBytes, SIGN_SEED);
  const parsed = parseFrame(raw);
  // Round-trip invariant: the parsed body re-encodes to the same bytes.
  const reencoded = encodeFrameBody(parsed.body);
  return {
    name,
    bodyHex: H(bodyBytes),
    signedFrameHex: H(raw),
    messageId: H(messageIdOf(bodyBytes, parsed.sig)),
    roundTrips: H(reencoded) === H(bodyBytes),
  };
}

function buildFramesVectors(): unknown {
  const sk = membership('did:web:001.fid.is', 0x0a, fill(32, 0x0b));
  const kp = generateSigningKeypair(() => fill(32, 0x02));
  const emptyExt = new Uint8Array(0); // no extensions ⇒ zero-length ext
  // A coverage frame's ext = ExtBody(digest, rotation) as opaque bytes.
  const covExt = encodeExt({
    digest: { digest: fill(32, 0xd1), heads: [fill(32, 0xa1)] },
    rotation: fill(32, 0x9c),
  });

  return {
    description:
      'Frame vectors (wire-format §3/§9): FrameBody → DRISL-profile CBOR (map-free) → Ed25519 ' +
      'SignedFrame → MessageID = SHA-256(body‖sig). Signing seed = 0x01³². Covers bootstrap zeroing ' +
      '(§2) and the opaque `ext` bytes (ext.ts). Byte-frozen; delete to regenerate.',
    signingSeed: H(SIGN_SEED),
    extBody: { digestRotation: H(covExt), decodedRoundTrips: extRoundTrips(covExt) },
    vectors: [
      frameVector('control-create-bootstrap-zeroing', {
        version: 1,
        groupId: ZERO32, // §2: zeroed in create
        sender: membership('did:web:001.fid.is', 0x0a, ZERO32), // §2: creator admittedBy zeroed
        seq: 0,
        ctrlSeq: 0,
        deps: [],
        cls: 1,
        payload: [1, [[[['did:web:001.fid.is', fill(32, 0x0a)], fill(32, 0x0c), kp.pk]], ['did:web:001.fid.is']]],
        ext: emptyExt,
      }),
      frameVector('app-frame', {
        version: 1,
        groupId: fill(32, 0x0d),
        sender: sk,
        seq: 7,
        ctrlSeq: null, // app frames are ctrlSeq-exempt
        deps: [fill(32, 0x0e)],
        cls: 3,
        payload: [3, fill(48, 0x0f)],
        ext: emptyExt,
      }),
      frameVector('coverage-with-opaque-ext', {
        version: 1,
        groupId: fill(32, 0x0d),
        sender: sk,
        seq: 2,
        ctrlSeq: 2,
        deps: [fill(32, 0x0e)],
        cls: 1,
        payload: [7, []], // coverage
        ext: covExt, // opaque bytes to the base codec
      }),
    ],
  };
}

function extRoundTrips(bytes: Uint8Array): boolean {
  const d = decodeExt(bytes);
  return d.digest !== undefined && d.rotation !== undefined && bytesToHex(d.rotation) === bytesToHex(fill(32, 0x9c));
}

// ── envelope vectors (sealed-sym; wire-format §6, §9 `envelopes/`) ────────────

function buildEnvelopeVectors(): unknown {
  const pcs = fill(32, 0x11);
  const sender: Membership = { device: { did: 'did:web:s', fingerprint: fill(32, 0x22) }, admittedBy: fill(32, 0x23) };
  const recipient: Membership = { device: { did: 'did:web:r', fingerprint: fill(32, 0x24) }, admittedBy: fill(32, 0x25) };
  const encS = encodeMembership(sender);
  const encR = encodeMembership(recipient);
  const envKey = envKeySym(pcs, encS);
  const tag = hintTag(envKey, encR);
  // Deterministic nonce for a frozen vector (real sends use a CSPRNG).
  const detNonce = fill(24, 0x30);
  const body = new TextEncoder().encode('frozen sealed-sym body');
  const env = sealSymTo(envKey, encR, CONTENT_FRAME, body, () => detNonce);
  const opened = openSym(envKey, env);

  return {
    description:
      'Sealed-sym envelope vectors (sealed-sender §11, wire-format §6). envKey = Expand(PcsKey, ' +
      '"atsms-seal:v1:sym"‖enc(sender)); tag = Expand(envKey, "atsms-seal:v1:hint"‖enc(recipient))[0..8]; ' +
      'XChaCha20-Poly1305, AAD = enc([1,2,tag]); plaintext padded to a bucket. Byte-frozen; delete to regen.',
    envKeySym: { pcsKey: H(pcs), encSender: H(encS), output: H(envKey) },
    hintTag: { envKey: H(envKey), encRecipient: H(encR), tag: H(tag) },
    padding: BUCKETS_probe(),
    sealSym: {
      nonce: H(detNonce),
      body: H(body),
      envelope: H(env),
      envelopeId: H(envelopeId(env)),
      opensTo: H(opened.body),
      envelopeLen: env.length,
    },
    sealAsym: (() => {
      // Deterministic HPKE ephemeral for a frozen KAT (real sends use a CSPRNG).
      // NB: pins OUR implementation; cross-check vs RFC 9180 A.2 is Phase-6.
      const skR = fill(32, 0x40);
      const pkR = x25519.getPublicKey(skR);
      const detEph = fill(32, 0x41);
      const abody = new TextEncoder().encode('frozen sealed-asym body');
      const aenv = sealAsymTo(pkR, CONTENT_FRAME, abody, () => detEph);
      const aopened = openAsym(skR, aenv);
      // A raw HPKE seal too (enc + ct) for a primitive-level KAT.
      const raw = sealBase(pkR, SEAL_ASYM_INFO, new Uint8Array(0), fill(16, 0x42), () => detEph);
      return {
        recipientSk: H(skR),
        recipientPk: H(pkR),
        ephemeralSk: H(detEph),
        body: H(abody),
        envelope: H(aenv),
        envelopeId: H(envelopeId(aenv)),
        opensTo: H(aopened.body),
        envelopeLen: aenv.length,
        hpkeRaw: { enc: H(raw.enc), ct: H(raw.ct), plaintext: H(fill(16, 0x42)) },
      };
    })(),
  };
}

function BUCKETS_probe(): Record<string, number> {
  // Freeze the padded length for a few body sizes (bucket discipline).
  const out: Record<string, number> = {};
  for (const len of [0, 300, 1024, 5000, 65000]) {
    out[`body${len}`] = padToBucket(CONTENT_FRAME, fill(len, 0xcd)).length;
  }
  return out;
}

// ── the freeze-or-verify harness ─────────────────────────────────────────────

function buildRecordVectors(): unknown {
  const utf8 = (s: string) => new TextEncoder().encode(s);
  const identitySk = blake3(utf8('records:identity-sk'), { dkLen: 32 });
  const identityPub = p256.getPublicKey(identitySk);
  const signedPrekey = x25519.getPublicKey(blake3(utf8('records:prekey-sk'), { dkLen: 32 }));
  const createdAt = '2026-07-26T00:00:00.000Z';
  const expiresAt = '2026-08-02T00:00:00.000Z';
  const prekey = buildPrekeyRecord({ signedPrekey, createdAt, expiresAt }, identitySk);
  const inbox = buildInboxRecord([
    { uri: 'https://relay.haiven.mobile/atsms/in/9d2e' },
    { uri: 'mailto:did!plc!abc123@haiven.mobile' },
  ]);
  return {
    note: 'at.atsms.prekey bundleSig = ECDSA-P256 (RFC 6979 deterministic) over SHA-256 of cbor([signedPrekey, createdAt, expiresAt]); at.atsms.inbox = ordered endpoints, mailto floor (identity-devices §4.2 / inbound-delivery §3).',
    prekey: {
      identityPubHex: bytesToHex(identityPub),
      signedPrekeyHex: bytesToHex(signedPrekey),
      createdAt,
      expiresAt,
      bundleSigInputHex: bytesToHex(prekeyBundleSigInput({ signedPrekey, createdAt, expiresAt })),
      bundleSigHex: bytesToHex(prekey.bundleSig),
    },
    inbox: { endpoints: inbox.endpoints.map((e) => e.uri) },
  };
}

function freezeOrVerify(name: string, fresh: unknown): void {
  const path = fileURLToPath(new URL(`../../../test-vectors/${name}.json`, import.meta.url));
  if (!existsSync(path)) {
    writeFileSync(path, JSON.stringify(fresh, null, 2) + '\n');
  }
  const frozen = JSON.parse(readFileSync(path, 'utf8'));
  expect(fresh, `${name}.json drift — review the wire change, then delete the file to regenerate`).toEqual(
    frozen,
  );
}

describe('frozen test vectors (wire-format §9)', () => {
  it('kdf vectors reproduce the frozen bytes', () => {
    freezeOrVerify('kdf', buildKdfVectors());
  });

  it('frame vectors reproduce the frozen bytes', () => {
    freezeOrVerify('frames', buildFramesVectors());
  });

  it('envelope vectors reproduce the frozen bytes', () => {
    freezeOrVerify('envelopes', buildEnvelopeVectors());
  });

  it('record vectors reproduce the frozen bytes', () => {
    freezeOrVerify('records', buildRecordVectors());
  });

  it('all frame vectors round-trip (parse ∘ encode = identity)', () => {
    const built = buildFramesVectors() as { vectors: { roundTrips: boolean }[] };
    for (const v of built.vectors) expect(v.roundTrips).toBe(true);
  });

  it('MessageID is SHA-256(body ‖ sig) and stable across re-parse', () => {
    const raw = signFrame(encodeFrameBody({
      version: 1,
      groupId: ZERO32,
      sender: membership('did:web:x', 1, ZERO32),
      seq: 0,
      ctrlSeq: 0,
      deps: [],
      cls: 1,
      payload: [7, []],
      ext: new Uint8Array(0),
    }), SIGN_SEED);
    const p1 = parseFrame(raw);
    const p2 = parseFrame(raw);
    expect(bytesToHex(p1.id)).toBe(bytesToHex(p2.id));
    expect(bytesToHex(p1.id)).toBe(bytesToHex(messageIdOf(p1.bodyBytes, p1.sig)));
  });
});

// keep imports used
void concatBytes;
void hexToBytes;
