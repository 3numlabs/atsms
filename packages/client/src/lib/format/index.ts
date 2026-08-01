/**
 * v2 message format (docs/message-format.md): deterministic-CBOR content,
 * derived IDs, the part-kind registry, constructors, and the shared render
 * model. This module owns the wire shape; the crypto and storage layers treat
 * the encoded bytes as opaque.
 */

export {
  callEventPart,
  callPart,
  type CallSignal,
  createContent,
  type CreateContentOptions,
  filePart,
  groupUpdatePart,
  INLINE_FILE_LIMIT,
  inlineFilePart,
  previewPart,
  reactionPart,
  receiptPart,
  smsPart,
  type TextFacet,
  textPart,
  typingPart,
} from "./build.js";
export { cborDecode, cborEncode,type CborMap, type CborMapKey, type CborValue } from "./cbor.js";
export { decodeContent, encodeContent, recipientsExtension } from "./content.js";
export {
  conversationConvoId,
  CONVO_CONVERSATION,
  CONVO_ID_LENGTH,
  CONVO_ONESHOT,
  convoIdFromHex,
  convoIdToHex,
  deriveMessageId,
  groupIdOfConvoId,
  isConvoId,
  MESSAGE_ID_LENGTH,
  messageIdFromHex,
  messageIdToHex,
  oneShotConvoIdV2,
} from "./ids.js";
export { type RenderModel, renderModel, textOf } from "./render.js";
export {
  CONTENT_VERSION,
  ENC_ALG_A128GCM,
  type Expiration,
  EXT_RECIPIENTS,
  type ExternalContent,
  type ExternalPart,
  HASH_ALG_SHA256,
  type InlinePart,
  KIND_CALL,
  KIND_CALL_EVENT,
  KIND_FILE,
  KIND_GROUP_UPDATE,
  KIND_PREVIEW,
  KIND_PRIVATE_USE,
  KIND_REACTION,
  KIND_RECEIPT,
  KIND_SMS,
  KIND_TEXT,
  KIND_TYPING,
  type MessageContent,
  type Part,
  PART_HANDLING,
  type PartHandling,
  partHandling,
} from "./types.js";
