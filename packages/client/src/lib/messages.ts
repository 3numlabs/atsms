/**
 * Message Manipulation Library
 * Handles creation, signing, encryption, decryption, and parsing of AT-SMS messages
 * This module is browser-compatible
 */

import { nanoid } from "nanoid";

import { ATSMSEndpointCertificate } from "./certificates/index";
import { cryptoProvider } from "./crypto-provider";
import { encryptMessage, signMessage } from "./crypto";
import {
  type ATProtoFacet,
  type ATSMSMessagePayload,
  type ATSMSTextContent,
  type ATSMSWebRTCContent,
} from "./types";

/**
 * Generate deterministic conversation ID for 1:1 DMs.
 * Both parties will compute the same ID given the same DIDs,
 * preventing duplicate conversations between the same two users.
 *
 * @param did1 - First participant DID
 * @param did2 - Second participant DID
 * @returns Deterministic convoId with "dm_" prefix
 */
export async function generateDMConvoId(
  did1: string,
  did2: string,
): Promise<string> {
  const sortedDids = [did1, did2].sort().join(",");
  const encoder = new TextEncoder();
  const data = encoder.encode(sortedDids);
  const hashBuffer = await cryptoProvider.subtle.digest("SHA-256", data);
  const hashArray = new Uint8Array(hashBuffer);
  const hashHex = Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `dm_${hashHex.substring(0, 16)}`;
}

/**
 * Check if a conversation ID is a deterministic DM ID
 */
export function isDMConvoId(convoId: string): boolean {
  return convoId.startsWith("dm_");
}

/**
 * Helper: Create content for "atsms/text" message
 * Returns JSON string ready to use in ATSMSMessagePayload.content
 *
 * @param text - The text content
 * @param facets - Optional AT Protocol facets (mentions, links, hashtags)
 * @returns JSON-serialized content
 */
export function createTextContent(
  text: string,
  facets?: ATProtoFacet[],
): string {
  const content: ATSMSTextContent = {
    text,
    ...(facets && facets.length > 0 && { facets }),
  };
  return JSON.stringify(content);
}

/**
 * Helper: Create content for "atsms/webrtc" message
 * Returns JSON string ready to use in ATSMSMessagePayload.content
 * Used for WebRTC signaling (offers, answers, ICE candidates)
 *
 * @param webrtcContent - WebRTC signaling data
 * @returns JSON-serialized content
 */
export function createWebRTCContent(webrtcContent: ATSMSWebRTCContent): string {
  return JSON.stringify(webrtcContent);
}

/**
 * Helper: Parse content from "atsms/webrtc" message
 *
 * @param content - JSON-serialized content from message
 * @returns Parsed WebRTC content
 */
export function parseWebRTCContent(content: string): ATSMSWebRTCContent {
  return JSON.parse(content) as ATSMSWebRTCContent;
}

/**
 * Create a message payload
 *
 * @param senderId - DID of sender
 * @param recipientIds - DIDs of recipients
 * @param content - JSON-serialized content (use createTextContent helper)
 * @param contentType - MIME type (default: "atsms/text")
 * @param conversationId - Optional conversation ID
 */
export function createMessagePayload(
  senderId: string,
  recipientIds: string[],
  content: string,
  contentType: string = "atsms/text",
  conversationId?: string,
): ATSMSMessagePayload {
  return {
    version: "1.0",
    contentType,
    id: nanoid(13),
    content,
    senderId,
    recipientIds,
    convoId: conversationId || nanoid(13),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Parse "atsms/text" content
 * Returns the parsed object for rendering
 *
 * @param content - JSON-serialized content
 * @returns Parsed content object with text and optional facets
 */
export function parseTextContent(content: string): ATSMSTextContent {
  try {
    const parsed = JSON.parse(content);
    if (typeof parsed.text !== "string") {
      throw new Error('Text content must have a "text" field');
    }
    return parsed as ATSMSTextContent;
  } catch (error) {
    throw new Error(`Failed to parse text content: ${error}`);
  }
}

/**
 * Sign and encrypt a message for sending
 */
export async function prepareMessageForSending(
  payload: ATSMSMessagePayload,
  senderCert: ATSMSEndpointCertificate,
  recipientCerts: ATSMSEndpointCertificate[],
): Promise<Uint8Array> {
  // 1. Serialize payload to JSON
  const messageContent = JSON.stringify(payload, null, 2);

  // 2. Sign the message
  const signedContent = await signMessage(messageContent, senderCert);

  // 3. Encrypt the signed content for recipients
  const encryptedContent = await encryptMessage(signedContent, recipientCerts);

  return encryptedContent;
}

/**
 * Extract P7M content from raw email
 */
export function extractP7MFromEmail(emailContent: string): {
  p7mContent: string;
  attachmentInfo: any;
} {
  try {
    // Enhanced boundary detection with multiple patterns
    let boundary: string | null = null;
    const boundaryPatterns = [
      /boundary[=:]\s*["']?([^"'\s;]+)/i,
      /boundary=\s*([^\s;]+)/i,
      /boundary:\s*([^\s;]+)/i,
    ];

    for (const pattern of boundaryPatterns) {
      const match = emailContent.match(pattern);
      if (match) {
        boundary = match[1];
        break;
      }
    }

    if (!boundary) {
      throw new Error("No boundary found in email - MIME parsing failed");
    }

    // Split email into parts with better boundary handling
    const boundaryDelimiters = [
      `--${boundary}`,
      `\r\n--${boundary}`,
      `\n--${boundary}`,
    ];
    let parts: string[] = [];

    for (const delimiter of boundaryDelimiters) {
      parts = emailContent.split(delimiter);
      if (parts.length > 1) {
        break;
      }
    }

    if (parts.length <= 1) {
      throw new Error(
        `Failed to split email into MIME parts using boundary: ${boundary}`,
      );
    }

    // Find the P7M attachment part with enhanced detection
    let attachmentPart: string | null = null;
    let attachmentInfo = {};
    let partIndex = -1;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];

      // Multiple detection patterns for P7M content
      const isP7MAttachment =
        (part.includes("application/pkcs7-mime") ||
          part.includes("application/x-pkcs7-mime") ||
          part.includes("message.p7m")) &&
        (part.includes("attachment") || part.includes("filename"));

      if (isP7MAttachment) {
        attachmentPart = part;
        partIndex = i;

        // Enhanced attachment info extraction
        const filenameMatch = part.match(/filename[=:]\s*["']?([^"'\s;]+)/i);
        const contentTypeMatch = part.match(/Content-Type:\s*([^;\r\n]+)/i);
        const encodingMatch = part.match(
          /Content-Transfer-Encoding:\s*([^\r\n\s]+)/i,
        );
        const dispositionMatch = part.match(
          /Content-Disposition:\s*([^;\r\n]+)/i,
        );

        attachmentInfo = {
          filename: filenameMatch ? filenameMatch[1] : "message.p7m",
          contentType: contentTypeMatch
            ? contentTypeMatch[1].trim()
            : "application/pkcs7-mime",
          encoding: encodingMatch ? encodingMatch[1].trim() : "base64",
          disposition: dispositionMatch
            ? dispositionMatch[1].trim()
            : "attachment",
          partIndex: partIndex,
          partLength: part.length,
        };

        break;
      }
    }

    if (!attachmentPart) {
      throw new Error(
        `No P7M attachment found in email - checked ${parts.length} MIME parts`,
      );
    }

    // Enhanced base64 content extraction with better line handling
    const lines = attachmentPart.split(/\r?\n/);
    let contentStarted = false;
    let base64Content = "";
    const headerLines: string[] = [];
    const contentLines: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmedLine = line.trim();

      // Track headers until we find empty line (indicating start of content)
      if (!contentStarted) {
        headerLines.push(line);
        // Empty line indicates end of headers and start of content
        if (trimmedLine === "") {
          contentStarted = true;
        }
        continue;
      }

      // Stop at boundary markers
      if (trimmedLine.startsWith("--")) {
        break;
      }

      // Accumulate base64 content (only non-empty lines after headers)
      if (trimmedLine.length > 0 && !trimmedLine.startsWith("Content-")) {
        base64Content += trimmedLine;
        contentLines.push(trimmedLine);
      }
    }

    if (base64Content.length === 0) {
      throw new Error(
        `No base64 content found in P7M attachment - content extraction failed`,
      );
    }

    // Validate base64 content and decode to check actual size
    let decodedSize = 0;
    try {
      const decoded = atob(base64Content);
      decodedSize = decoded.length;
    } catch (error) {
      throw new Error(`Invalid base64 content in P7M attachment: ${error}`);
    }

    // Add extraction metadata to attachment info
    (attachmentInfo as any).extractionMetadata = {
      totalParts: parts.length,
      headerLinesCount: headerLines.length,
      contentLinesCount: contentLines.length,
      base64Length: base64Content.length,
      decodedSize: decodedSize,
      extractionTimestamp: new Date().toISOString(),
    };

    return {
      p7mContent: base64Content,
      attachmentInfo: attachmentInfo,
    };
  } catch (error) {
    throw new Error(
      `Failed to extract P7M from email: ${error.message || error}`,
    );
  }
}
