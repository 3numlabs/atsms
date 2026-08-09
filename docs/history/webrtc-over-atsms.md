# WebRTC over ATSMS: Lessons Learned

> **Historical (2026-08-01):** these lessons were learned when signaling messages were persisted
> like chat and filtered at render time. The v2 message format's ephemeral class
> (`spec/message-format.md` §8) removes that class of bug at the root — signaling is never
> persisted, never replayed, and staleness is enforced at the receive layer. Lessons 1–4 below are
> retired as workarounds but kept as design rationale; the E2E-means-relay-can't-filter observation
> (and its metadata trade-off) remains current.

This document captures the issues encountered and fixes applied while implementing WebRTC audio/video calling over the ATSMS encrypted messaging transport.

## Architecture

WebRTC signaling (offer, answer, ICE candidates, hangup) is sent as regular ATSMS messages with `contentType: "atsms/webrtc"`. Messages are end-to-end encrypted using the same PKCS#7/CMS pipeline as text messages. The ATSMS inbox provider has no knowledge of message content types due to E2E encryption.

## Issue 1: Message Replay / Echo

**Problem:** The sender's own outgoing WebRTC messages were echoed back via the `messageAdded$` observable. When the caller sent an offer, it was echoed back to them. The caller's `handleSignalingMessage` processed its own offer as an incoming call, found itself busy ("outgoing-ringing"), and auto-declined — sending a hangup back to the callee.

**Fix:** Filter out messages where `senderId === currentDid` at the top of `handleSignalingMessage`.

## Issue 2: Stale Message Replay on Sync

**Problem:** Without persistent IndexedDB, every session starts `syncMessages` from sequence 0, replaying the entire inbox. Old WebRTC signaling messages (offers, hangups, ICE candidates from previous calls) were processed as if they were new. This caused:
- Old offers triggering incoming call UI
- Old hangups terminating new calls
- Old ICE candidates being buffered for non-existent connections

**Fix (temporary):** Store `lastSyncRev` in localStorage and seed it into IndexedDB on each session init. This makes `syncMessages` only fetch messages newer than the last known sequence. A proper fix is to enable IndexedDB persistence so the library's built-in sync tracking works across sessions.

**Fix (signaling layer):** Added a 30-second timestamp filter — any WebRTC message older than 30 seconds is silently dropped. All outgoing signaling includes `timestamp: Date.now()`. Messages without timestamps are also dropped (old messages from before timestamps were added).

## Issue 3: Duplicate Message Delivery

**Problem:** Both `syncMessages` (HTTP poll) and the WebSocket `new_message` broadcast deliver the same message. The `processIncomingTransportMessage` pipeline saves to IndexedDB and emits via `messageAdded$`. Without persistence, the duplicate check (`storage.getMessage(id)`) always misses because IndexedDB is empty. This caused:
- Duplicate offers → callee processes offer twice, second time is "busy" → auto-decline hangup
- Duplicate answers → caller applies answer twice, second time fails with "unexpected answer"

**Fix:**
- **Offers:** Check if `store.callId === webrtc.callId` before processing. If the callId already matches the active call, it's a duplicate — silently ignore.
- **Answers:** Check if status is already "connecting" or "connected" before processing. If so, the answer was already applied — silently ignore.
- Both fixes make the handlers idempotent for the same callId.

## Issue 4: Missing Timestamps on ICE Candidates

**Problem:** ICE candidates sent from `onicecandidate` didn't include `timestamp` in the signaling payload. The 30-second stale message filter treated messages without timestamps as infinitely old and dropped them. This caused ICE negotiation to fail silently — no candidates were exchanged, and the connection stayed in "connecting" forever.

**Fix:** Add `timestamp: Date.now()` to ICE candidate signaling messages in the `onicecandidate` handler. All WebRTC signaling messages must include timestamps.

## Issue 5: No Audio in Audio-Only Calls

**Problem:** The `CallOverlay` component only rendered a `<video>` element for video calls. For audio-only calls, the remote `MediaStream` (which contains audio tracks) was never attached to any media element, so no audio played.

**Fix:** Added a hidden `<audio>` element that always has the remote stream attached, regardless of call type. This ensures audio plays for both audio-only and video calls.

## Issue 6: E2E Encryption Prevents Server-Side Filtering

**Problem:** Initially considered having the ATSMS worker treat WebRTC messages as ephemeral (deliver via WebSocket only, don't persist). This would prevent replay entirely.

**Decision:** This approach violates the E2E encryption design — the inbox provider cannot inspect encrypted payloads to determine content type. All filtering must happen client-side after decryption.

## Design Principles

1. **All signaling messages must include `timestamp`** — this is the primary defense against stale message replay.
2. **Handlers must be idempotent** — the same message may arrive multiple times via different delivery paths (sync + WebSocket).
3. **Filter by sender** — always ignore your own messages echoed back through the system.
4. **Filter by state** — only process messages that make sense for the current call state (e.g., ignore hangups when idle).
5. **Filter by callId** — ignore messages for a different call than the one currently active.
6. **Audio needs explicit elements** — WebRTC `MediaStream` audio doesn't play automatically; it must be attached to an `<audio>` or `<video>` DOM element.
