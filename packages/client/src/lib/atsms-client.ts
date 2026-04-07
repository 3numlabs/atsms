/**
 * ATSMSClient - Library for AT Protocol secure messaging
 * This is the core library that handles messaging operations
 * Uses P-256 ECDSA endpoint certificates
 */

import { AtpAgent } from "@atproto/api";

import {
  ATSMSEndpointCertificate,
  loadEndpointCertificate,
} from "./certificates/index";

export class ATSMSClient {
  public agent: AtpAgent;
  public did: string;

  constructor(agent: AtpAgent, did: string) {
    if (!agent) {
      throw new Error("AtpAgent is required");
    }
    if (!did || !did.startsWith("did:")) {
      throw new Error("Valid DID is required");
    }

    this.agent = agent;
    this.did = did;
  }

  /**
   * Store endpoint certificate in PDS
   */
  async storeEndpointCertificate(
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<void> {
    const endpointCertPEM = endpointCert.certificatePEM;
    const serialNumber = endpointCert.serialNumber;
    const validUntil = endpointCert.notAfter.toISOString();
    const createdAt = new Date().toISOString();

    try {
      await this.agent.com.atproto.repo.putRecord({
        repo: this.did,
        collection: "at.atsms.x509",
        rkey: serialNumber,
        record: {
          certificate: endpointCertPEM,
          serialNumber: serialNumber,
          validUntil: validUntil,
          createdAt: createdAt,
          $type: "at.atsms.x509",
        },
      });
    } catch (error: any) {
      console.error("Failed to store endpoint certificate:", error);
      throw new Error(
        `Failed to store endpoint certificate: ${error.message || error}`,
      );
    }
  }

  /**
   * Resolve a DID to its PDS URL by fetching the DID document
   */
  private async resolveDIDToPDS(did: string): Promise<string> {
    try {
      // Fetch the DID document from PLC directory
      const response = await fetch(`https://plc.directory/${did}`);
      if (!response.ok) {
        console.error(`Failed to resolve DID ${did}: ${response.status}`);
        return "";
      }

      const didDoc = (await response.json()) as any;
      const pdsEndpoint = didDoc.service?.find(
        (s: any) =>
          s.type === "AtprotoPersonalDataServer" || s.id === "#atproto_pds",
      );

      return pdsEndpoint?.serviceEndpoint || "";
    } catch (error) {
      console.error(`Failed to resolve DID to PDS: ${error}`);
      return "";
    }
  }

  /**
   * Get user certificates from their PDS
   * Returns all endpoint certificates for the user
   * @param did - The DID to fetch certificates for (must be a valid DID)
   */
  async getUserCertificates(did: string): Promise<{
    endpointCerts: ATSMSEndpointCertificate[];
    error?:
      | "NOT_ATPROTO_USER"
      | "NO_ATSMS_CERTS"
      | "NO_ENDPOINT_CERTS"
      | "FETCH_ERROR";
  }> {
    const endpointCerts: ATSMSEndpointCertificate[] = [];

    try {
      // Resolve DID to PDS URL
      const pdsUrl = await this.resolveDIDToPDS(did);
      if (!pdsUrl) {
        // This means the DID doesn't exist or can't be resolved
        console.warn(
          `DID ${did} is not a valid AT Protocol user (could not resolve to PDS)`,
        );
        return {
          endpointCerts: [],
          error: "NOT_ATPROTO_USER",
        };
      }

      // Create an unauthenticated agent for the target PDS
      const targetAgent = new AtpAgent({ service: pdsUrl });

      // List all X.509 certificate records from the target PDS
      const response = await targetAgent.com.atproto.repo.listRecords({
        repo: did,
        collection: "at.atsms.x509",
        limit: 100,
      });

      // Check if user has any certificates
      if (!response.data.records || response.data.records.length === 0) {
        console.log(`User ${did} has not set up AT-SMS certificates`);
        return {
          endpointCerts: [],
          error: "NO_ATSMS_CERTS",
        };
      }

      // Parse the results into endpoint certificates
      for (const record of response.data.records) {
        try {
          const certPEM = (record.value as any)?.certificate;
          if (!certPEM) continue;

          const endpointCert = loadEndpointCertificate(certPEM);
          endpointCerts.push(endpointCert);
        } catch (error) {
          console.error("Error parsing certificate from record:", error);
        }
      }

      // Check if we found valid certificates
      if (endpointCerts.length === 0) {
        return {
          endpointCerts: [],
          error: "NO_ENDPOINT_CERTS",
        };
      }

      return {
        endpointCerts,
      };
    } catch (error: any) {
      // Handle specific error cases
      if (error.status === 400 || error.status === 404) {
        console.warn(`User ${did} not found or invalid AT Protocol account`);
        return {
          endpointCerts: [],
          error: "NOT_ATPROTO_USER",
        };
      }

      console.error(`Failed to retrieve certificates for DID ${did}:`, error);
      return {
        endpointCerts: [],
        error: "FETCH_ERROR",
      };
    }
  }
}
