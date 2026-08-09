/**
 * The shared render model (docs/message-format.md §5.2 — normative for all
 * clients): given decoded content, decide what renders, what applies, what
 * signals, and how unknown kinds degrade. Every reference client consumes
 * this instead of inventing its own policy.
 */

import type { CborValue } from "./cbor.js";
import type { MessageContent, Part } from "./types.js";
import { KIND_TEXT, partHandling } from "./types.js";

export interface RenderModel {
  /** Known render-class parts, in order. */
  renderParts: Part[];
  /** Known apply-class parts (reactions, receipts, group updates). */
  applyParts: Part[];
  /** Known signal-class parts (call signaling, typing). */
  signalParts: Part[];
  /**
   * §5.2 outcome when nothing renderable was understood:
   * - "fallback": render `fallbackText` as plain text with an "unsupported" affordance;
   * - "hidden": store but don't render, don't bump unread;
   * - null: at least one render part was understood (or this is a pure
   *   apply/signal/tombstone message — nothing was *supposed* to render).
   */
  degraded: "fallback" | "hidden" | null;
  fallbackText: string;
  /** True when the message is a retraction tombstone (`body: null` + replaces). */
  tombstone: boolean;
}

export function renderModel(content: MessageContent): RenderModel {
  const renderParts: Part[] = [];
  const applyParts: Part[] = [];
  const signalParts: Part[] = [];
  let unknownCount = 0;

  for (const part of content.body ?? []) {
    switch (partHandling(part.kind)) {
      case "render":
        renderParts.push(part);
        break;
      case "apply":
        applyParts.push(part);
        break;
      case "signal":
        signalParts.push(part);
        break;
      case null:
        unknownCount++;
        break;
    }
  }

  const tombstone = content.body === null && content.replaces !== null;
  let degraded: RenderModel["degraded"] = null;
  if (renderParts.length === 0 && unknownCount > 0) {
    degraded = content.fallback !== "" ? "fallback" : "hidden";
  }
  return { renderParts, applyParts, signalParts, degraded, fallbackText: content.fallback, tombstone };
}

/**
 * Plain-text summary of a message for simple surfaces (CLI lines, notification
 * previews, conversation-list snippets): the first text part, else the
 * fallback, else a filename/label for known non-text parts, else null
 * (nothing presentable — never raw structure, per §5.2).
 */
export function textOf(content: MessageContent): string | null {
  const model = renderModel(content);
  if (model.tombstone) return null;
  for (const part of model.renderParts) {
    if (part.kind === KIND_TEXT && "body" in part) {
      const text = part.body.get("text");
      if (typeof text === "string") return text;
    }
  }
  for (const part of model.renderParts) {
    const label = partLabel(part);
    if (label !== null) return label;
  }
  return model.degraded === "fallback" ? model.fallbackText : null;
}

function partLabel(part: Part): string | null {
  if ("external" in part) {
    const filename = part.external.meta.get("filename");
    return typeof filename === "string" ? filename : part.external.contentType;
  }
  const filename: CborValue | undefined = part.body.get("filename");
  if (typeof filename === "string") return filename;
  const ct = part.body.get("contentType");
  return typeof ct === "string" ? ct : null;
}
