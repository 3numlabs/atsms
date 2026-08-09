# @atsms/sms

The client SDK for **ATSMS**, an open protocol for end-to-end encrypted messaging and calling on AT
Protocol identities. It handles the cryptography, the storage, and the delivery, and gives an
application two things to work with: a way to send a one-off message, and a conversation object.

Group encryption comes from [`@atsms/dcgka`](../atsms-dcgka), which reaches agreement on keys with **no
server ordering anything** — no sequencer, no delivery service, no privileged party.

> **Proof of concept.** The cryptography has not been through an independent security review, which is a
> gating requirement before any of this carries real traffic. See
> [`SECURITY.md`](./SECURITY.md), and the protocol's
> [`KNOWN-ISSUES.md`](../atsms-dcgka/KNOWN-ISSUES.md) for what we already know is unfinished.
> Unreleased: the package is not on npm and the API is still moving.

## Install

```bash
bun add @atsms/sms
```

Developed and tested with bun. Runs in Node and in browsers; a browser bundle must alias `ws` to a stub.

## The two surfaces

**`send()` is a verb.** One message to someone you have no conversation with — the "certified mail"
surface. It carries no ongoing state and reaches anyone with a published certificate, including devices
that do not speak the group-encryption layer.

**`conversations` is a noun.** It holds keys and membership over time. Two ways in, because they are two
different acts: a direct conversation with someone always conceptually exists, so you open it and asking
twice returns the same one; a group is something you *make*, and the same people may share any number of
them.

```typescript
import { ATSMS } from "@atsms/sms";

const atsms = await ATSMS.create({ identity, storage, transport, pds, rng });

// Stateless: one message, no conversation.
await atsms.send({ to: theirDid, text: "hello" });

// Stateful: a direct conversation, or a group.
const dm = await atsms.conversations.with(theirDid);
const group = await atsms.conversations.createGroup({
  members: [aDid, anotherDid],
  title: "Trip to Kyoto",
});

await group.send("we land at six");
group.messages$.subscribe((messages) => render(messages));

await group.addMember(someoneElse);   // admin only
await group.rename("Kyoto 2027");     // shared: every member sees it
await group.leave();
```

Messages arrive fully processed — decrypted, verified, ordered, deduplicated, and persisted — through
`messages$`. Nothing above this layer touches a key.

## What you supply

`ATSMS.create()` takes five things, so the library never assumes a platform:

| | |
|---|---|
| `identity` | this device's certificate and keys (`ATSMSDeviceIdentity`) |
| `storage` | a `StorageAdapter` — `SQLiteAdapter`, `IndexedDBAdapter`, or your own, optionally wrapped in `EncryptedStorageAdapter` for encryption at rest |
| `transport` | an `EnvelopeTransport` — how sealed envelopes reach a relay. `ATSMSWorkerEnvelopeTransport` speaks to the reference relay |
| `pds` | an AT Protocol agent, for publishing and resolving records |
| `rng` | a source of randomness |

Optional: `onEvent` for diagnostics, `onSignal` for call signalling, `onMetric` for timing samples.

## Reading the code

Start with [`atsms-cli`](../atsms-cli), a terminal client that is a thin layer over this API and small
enough to read in one sitting. [`atsms-demo`](../atsms-demo) is the browser equivalent, including calls.

Inside this repository, [`CLAUDE.md`](./CLAUDE.md) is the accurate map of the modules and the load-bearing
facts about them.

## Where things live

The protocol itself — specifications, the group-encryption engine, the record schemas, and the review
brief — is in [`atsms-dcgka`](../atsms-dcgka). This repository is the client library that implements it.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
