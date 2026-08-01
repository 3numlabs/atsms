/**
 * Publish a device's endpoint certificate as its `at.atsms.x509` record —
 * rkey = device fingerprint (identity-devices §4), the structural pair of
 * `at.atsms.prekey/<fingerprint>`; the serial stays a field of the artifact.
 */

import type { PdsClient } from "@atsms/dcgka";

import type { ATSMSEndpointCertificate } from "../certificates/index.js";

const COLLECTION_X509 = "at.atsms.x509";

export async function publishEndpointCertificate(
  pds: PdsClient,
  cert: ATSMSEndpointCertificate,
): Promise<void> {
  const fingerprint = await cert.getDeviceFingerprint();
  await pds.putRecord(COLLECTION_X509, fingerprint, {
    $type: COLLECTION_X509,
    certificate: cert.certificatePEM,
    serialNumber: cert.serialNumber,
    validUntil: cert.notAfter.toISOString(),
    createdAt: new Date().toISOString(),
  });
}
