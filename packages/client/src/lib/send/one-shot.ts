/**
 * The stateless one-shot path (sdk-shape.md Part A: `atsms.send()`) — the
 * **X509 baseline**: sign-then-encrypt to every recipient device's endpoint
 * cert, no session, no persisted crypto state. This is what reaches recipients
 * who are not DCGKA-capable, and what carries first contact.
 *
 * v2 (docs/message-format.md §8): the CMS plaintext is the deterministic-CBOR
 * `MessageContent`, and the CMS itself travels **inside the sealed-sender
 * envelope** (`CONTENT_CMS`) whenever the recipient device published a prekey
 * to seal to; recipients with only an X509 certificate get the bare CMS as
 * the explicit legacy form. Dispatch reads the declared sealed content type —
 * bare DER remains recognizable as "not CBOR" without sniffing heuristics.
 *
 * Trust: the CMS signature is verified against the embedded signer cert, and
 * then the signer cert must RESOLVE in its DID's `at.atsms.x509` collection
 * at its fingerprint rkey — an unpublished (or mismatched) signer is dropped.
 * The sender identity IS the authenticated signer; the content carries no
 * sender field. `convoId` is deterministic over the participant set (the
 * signer + the `EXT_RECIPIENTS` extension), so a verified sender still
 * cannot inject into an arbitrary thread.
 */

import type { PdsClient } from "@atsms/dcgka";

import { type ATSMSEndpointCertificate, loadEndpointCertificate } from "../certificates/index.js";
import { decryptAndVerifyMessageSignature } from "../crypto.js";
import { decodeContent, type MessageContent } from "../format/index.js";
import { prepareMessageForSending } from "../messages.js";

const COLLECTION_X509 = "at.atsms.x509";

/** A DID's valid endpoint certs (its devices), from its `at.atsms.x509` records. */
export async function resolveRecipientCerts(
  pds: PdsClient,
  did: string,
): Promise<ATSMSEndpointCertificate[]> {
  const records = await pds.listRecords(did, COLLECTION_X509);
  const certs: ATSMSEndpointCertificate[] = [];
  for (const rec of records) {
    const pem = (rec.value as { certificate?: unknown }).certificate;
    if (typeof pem !== "string") continue;
    try {
      const cert = loadEndpointCertificate(pem);
      if (cert.isValid()) certs.push(cert);
    } catch {
      // unparseable record — not a device
    }
  }
  return certs;
}

/** Sign (PKCS#7) then encrypt (CMS EnvelopedData) v2 content bytes to every
 *  recipient device cert. Returns the CMS DER (seal or deliver bare — §8). */
export function sealOneShot(
  contentBytes: Uint8Array,
  senderCert: ATSMSEndpointCertificate,
  recipientCerts: ATSMSEndpointCertificate[],
): Promise<Uint8Array> {
  return prepareMessageForSending(contentBytes, senderCert, recipientCerts);
}

export interface OpenedOneShot {
  content: MessageContent;
  /** The exact signed plaintext bytes — what the message ID derives from. */
  contentBytes: Uint8Array;
  signer: ATSMSEndpointCertificate;
}

/**
 * Decrypt with this device's cert, verify the CMS signature, and decode the
 * v2 content. Throws when the blob is not addressed to this device or the
 * signature/content is invalid. Sender AUTHENTICITY (signer published under
 * its DID) is the caller's next step — it needs PDS access.
 */
export async function openOneShot(
  bytes: Uint8Array,
  myCert: ATSMSEndpointCertificate,
): Promise<OpenedOneShot> {
  const { messageSigner, decryptedContent } = await decryptAndVerifyMessageSignature(bytes, myCert);
  const content = decodeContent(decryptedContent); // throws on non-v2 shapes
  return { content, contentBytes: decryptedContent, signer: messageSigner };
}

/**
 * Sender authenticity (the fingerprint-keyed check, integration §8.5): a
 * record for the signer's fingerprint must exist in the signer DID's
 * `at.atsms.x509` collection with the same public key. Returns null when
 * authentic, else the reason to drop.
 */
export async function oneShotSenderProblem(
  pds: PdsClient,
  signer: ATSMSEndpointCertificate,
): Promise<string | null> {
  const did = signer.did;
  if (did === undefined) return "signer certificate carries no DID";
  const fingerprint = await signer.getDeviceFingerprint();
  const rec = await pds.getRecord(did, COLLECTION_X509, fingerprint);
  if (rec === null) return `signer ${fingerprint.slice(0, 12)}… not published under ${did}`;
  const pem = (rec.value as { certificate?: unknown }).certificate;
  if (typeof pem !== "string") return "published record has no certificate";
  try {
    const published = loadEndpointCertificate(pem);
    if ((await published.getDeviceFingerprint()) !== fingerprint) {
      return "published record's key does not match its rkey";
    }
  } catch {
    return "published record's certificate is unparseable";
  }
  return null;
}
