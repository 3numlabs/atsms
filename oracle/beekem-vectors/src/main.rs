//! Differential-oracle vector generator for the @atsms/dcgka BeeKEM port.
//! Drives the upstream `beekem` crate with injected deterministic secrets and
//! dumps expected values (root secrets, cipher samples) as JSON.

use beekem::{
    id::{MemberId, TreeId},
    keys::{NodeKey, ShareKeyMap},
    tree::BeeKem,
};
use ed25519_dalek::SigningKey;
use keyhive_crypto::share_key::ShareSecretKey;
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};

fn member_id(i: u8) -> MemberId {
    MemberId(SigningKey::from([i; 32]).verifying_key())
}

fn doc_id() -> TreeId {
    TreeId(SigningKey::from([0xD0u8; 32]).verifying_key())
}

/// Deterministic leaf secret: fill pattern (label, counter).
fn secret(label: u8, ctr: u8) -> ShareSecretKey {
    let mut b = [0u8; 32];
    for (j, x) in b.iter_mut().enumerate() {
        *x = label ^ ctr.wrapping_mul(37) ^ (j as u8);
    }
    ShareSecretKey::force_from_bytes(b)
}

struct Member {
    id: MemberId,
    sks: ShareKeyMap,
    ctr: u8,
    label: u8,
}

impl Member {
    fn new(i: u8) -> Self {
        let mut m = Member {
            id: member_id(i),
            sks: ShareKeyMap::new(),
            ctr: 0,
            label: i,
        };
        let sk = m.next_secret();
        m.sks.insert(sk.share_key(), sk);
        m
    }

    fn next_secret(&mut self) -> ShareSecretKey {
        let s = secret(self.label, self.ctr);
        self.ctr += 1;
        s
    }

    fn initial_pk(&self) -> keyhive_crypto::share_key::ShareKey {
        secret(self.label, 0).share_key()
    }
}

fn update(tree: &mut BeeKem, m: &mut Member, rng: &mut StdRng) -> (String, String) {
    let sk = m.next_secret();
    let pk = sk.share_key();
    m.sks.insert(pk, sk);
    let (pcs, _path) = tree
        .encrypt_path(m.id, pk, &mut m.sks, rng)
        .expect("encrypt_path")
        .expect("id present");
    (hex::encode(sk.to_bytes()), hex::encode(pcs.0.to_bytes()))
}

fn seq_scenario(n: u8, updaters: &[u8], rng: &mut StdRng) -> Value {
    let mut members: Vec<Member> = (0..n).map(Member::new).collect();
    let mut tree = BeeKem::new(doc_id(), members[0].id, members[0].initial_pk()).unwrap();
    for m in members.iter().skip(1) {
        tree.push_leaf(m.id, NodeKey::ShareKey(m.initial_pk()));
    }
    let mut steps = Vec::new();
    for &u in updaters {
        let (new_sk_hex, root_hex) = update(&mut tree, &mut members[u as usize], rng);
        // Rust-side sanity: every member derives the same root.
        for m in members.iter_mut() {
            let derived = tree.decrypt_tree_secret(m.id, &mut m.sks).expect("decrypt");
            assert_eq!(hex::encode(derived.to_bytes()), root_hex, "member decrypt mismatch");
        }
        steps.push(json!({
            "op": "update",
            "member": u,
            "newLeafSk": new_sk_hex,
            "expectRootSecret": root_hex,
        }));
    }
    json!({
        "name": format!("seq_n{}_u{:?}", n, updaters),
        "docId": hex::encode(doc_id().to_bytes()),
        "members": (0..n).map(|i| json!({
            "id": hex::encode(member_id(i).to_bytes()),
            "initialSk": hex::encode(secret(i, 0).to_bytes()),
        })).collect::<Vec<_>>(),
        "steps": steps,
    })
}

fn concurrent_scenario(rng: &mut StdRng) -> Value {
    // n=4; member 0 and member 3 update concurrently on replicas A and B;
    // cross-apply; member 1 resolves. Expected root after resolution.
    let build = |members: &mut Vec<Member>| -> BeeKem {
        let mut tree = BeeKem::new(doc_id(), members[0].id, members[0].initial_pk()).unwrap();
        for m in members.iter().skip(1) {
            tree.push_leaf(m.id, NodeKey::ShareKey(m.initial_pk()));
        }
        tree
    };
    let mut members: Vec<Member> = (0..4).map(Member::new).collect();
    let mut members_b: Vec<Member> = (0..4).map(Member::new).collect();
    let mut tree_a = build(&mut members);
    let mut tree_b = build(&mut members_b);

    // Concurrent updates (same deterministic next-secrets on both sides).
    let sk_a = {
        let m = &mut members[0];
        let sk = m.next_secret();
        m.sks.insert(sk.share_key(), sk);
        sk
    };
    let (_pcs_a, path_a) = tree_a
        .encrypt_path(members[0].id, sk_a.share_key(), &mut members[0].sks, rng)
        .unwrap()
        .unwrap();
    let sk_b = {
        let m = &mut members_b[3];
        let sk = m.next_secret();
        m.sks.insert(sk.share_key(), sk);
        sk
    };
    let (_pcs_b, path_b) = tree_b
        .encrypt_path(members_b[3].id, sk_b.share_key(), &mut members_b[3].sks, rng)
        .unwrap()
        .unwrap();

    tree_a.apply_path(&path_b);
    tree_b.apply_path(&path_a);

    // Resolve on A via member 1.
    let sk_r = {
        let m = &mut members[1];
        let sk = m.next_secret();
        m.sks.insert(sk.share_key(), sk);
        sk
    };
    let (pcs, _path_r) = tree_a
        .encrypt_path(members[1].id, sk_r.share_key(), &mut members[1].sks, rng)
        .unwrap()
        .unwrap();
    let root_hex = hex::encode(pcs.0.to_bytes());

    // Sanity: members 0 and 1 decrypt on A (3's rotated secret lives on B side).
    for m in members.iter_mut().take(2) {
        let derived = tree_a.decrypt_tree_secret(m.id, &mut m.sks).unwrap();
        assert_eq!(hex::encode(derived.to_bytes()), root_hex);
    }

    json!({
        "name": "concurrent_n4_a0_b3_resolve1",
        "docId": hex::encode(doc_id().to_bytes()),
        "members": (0..4).map(|i| json!({
            "id": hex::encode(member_id(i).to_bytes()),
            "initialSk": hex::encode(secret(i, 0).to_bytes()),
        })).collect::<Vec<_>>(),
        "aUpdaterSk": hex::encode(sk_a.to_bytes()),
        "bUpdaterSk": hex::encode(sk_b.to_bytes()),
        "resolverSk": hex::encode(sk_r.to_bytes()),
        "expectRootSecret": root_hex,
    })
}

fn cipher_samples() -> Value {
    // Direct byte-level cross-checks of the keyhive constructions.
    let sk = ShareSecretKey::force_from_bytes([0x11; 32]);
    let paired = ShareSecretKey::force_from_bytes([0x22; 32]).share_key();
    let secret_pt = ShareSecretKey::force_from_bytes([0x33; 32]);
    let doc = [0xD7u8; 32];
    let enc = beekem::encrypted::encrypt_secret(&doc, secret_pt, &sk, &paired).unwrap();
    json!({
        "encryptSecret": {
            "docId": hex::encode(doc),
            "sk": hex::encode(sk.to_bytes()),
            "pairedPk": hex::encode(paired.to_bytes()),
            "secret": hex::encode(secret_pt.to_bytes()),
            "nonce": hex::encode(enc.nonce.as_bytes()),
            "ciphertext": hex::encode(&enc.ciphertext),
        },
        "ratchetForward": {
            "in": hex::encode([0x44u8; 32]),
            "out": hex::encode(ShareSecretKey::force_from_bytes([0x44; 32]).ratchet_forward().to_bytes()),
        },
        "deriveSymmetricKey": {
            "sk": hex::encode([0x55u8; 32]),
            "pk": hex::encode(ShareSecretKey::force_from_bytes([0x66; 32]).share_key().to_bytes()),
            "out": hex::encode(<[u8;32]>::from(ShareSecretKey::force_from_bytes([0x55; 32])
                .derive_symmetric_key(&ShareSecretKey::force_from_bytes([0x66; 32]).share_key()))),
        },
        "shareKeyOf": {
            "in": hex::encode([0x77u8; 32]),
            "out": hex::encode(ShareSecretKey::force_from_bytes([0x77; 32]).share_key().to_bytes()),
        }
    })
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0);
    let out = json!({
        // Records WHICH upstream revision produced these vectors, so a
        // reviewer can reproduce them exactly. Pass it in when generating:
        //   KEYHIVE_COMMIT=$(git -C ../keyhive rev-parse HEAD) cargo run --release
        "generator": format!(
            "beekem-vectors (inkandswitch/keyhive @ {})",
            option_env!("KEYHIVE_COMMIT").unwrap_or("unrecorded; see oracle/README.md")
        ),
        "scenarios": [
            seq_scenario(1, &[0], &mut rng),
            seq_scenario(2, &[0, 1], &mut rng),
            seq_scenario(3, &[0, 2], &mut rng),
            seq_scenario(5, &[4, 0, 2], &mut rng),
            seq_scenario(9, &[0, 8, 3], &mut rng),
        ],
        "concurrent": concurrent_scenario(&mut rng),
        "cipherSamples": cipher_samples(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
