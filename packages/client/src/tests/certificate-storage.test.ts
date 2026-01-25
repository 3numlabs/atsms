/**
 * Tests for certificate storage functionality
 */

import { Database } from "bun:sqlite";
import { beforeEach, describe, expect, test } from "bun:test";

import { PasswordEncryption } from "../lib/crypto/password-encryption";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter";

// SQLite wrapper for Bun compatibility
class BunSQLiteWrapper {
  private db: Database;

  constructor(path: string) {
    this.db = new Database(path);
  }

  exec(sql: string): void {
    this.db.exec(sql);
  }

  prepare(sql: string) {
    const stmt = this.db.prepare(sql);
    return {
      run: (...params: any[]) => stmt.run(...params),
      get: (...params: any[]) => stmt.get(...params),
      all: (...params: any[]) => stmt.all(...params),
    };
  }

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  close() {
    this.db.close();
  }
}

describe("Certificate Storage", () => {
  let adapter: SQLiteAdapter;
  let db: BunSQLiteWrapper;

  beforeEach(() => {
    // Use in-memory database for tests
    db = new BunSQLiteWrapper(":memory:");
    adapter = new SQLiteAdapter(db as any);
  });

  test("should save and retrieve certificate without encryption", async () => {
    const did = "did:plc:test123";
    const certificatePEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+6ADAgECAgkAu7GVVfU7RAowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwP
c2t5Zmkuc29jaWFsIENBMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFow
GjEYMBYGA1UEAwwPdGVzdC5za3lmaS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3qywJtC5IxIDJRr4JSdBHBXBj6h+dK
FhnoHEQQzcIASJYqiwnjz7FZvlCrowIwADAKBggqhkjOPQQDAgNIADBFAiEA8Mwl
tOpA8eBWCGev2pG8LfrCNy6QZ1n7zP5cVL0cg5wCIF3rWGlFF4F3mOhHSQcKBJMx
p1J7dq0cL7a3AQ3sVoX9
-----END CERTIFICATE-----`;
    const privateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`;

    await adapter.saveCertificate(
      did,
      "root",
      "test-serial-123",
      certificatePEM,
      privateKeyPEM,
      false,
      { issuer: "Test CA" },
    );

    const retrieved = await adapter.getCertificate(
      did,
      "root",
      "test-serial-123",
    );
    expect(retrieved).toBeDefined();
    expect(retrieved?.certificatePEM).toBe(certificatePEM);
    expect(retrieved?.privateKeyPEM).toBe(privateKeyPEM);
    expect(retrieved?.isEncrypted).toBe(false);
    expect(retrieved?.metadata?.issuer).toBe("Test CA");
  });

  test("should save and retrieve certificate with encryption", async () => {
    const did = "did:plc:test456";
    const password = "test-password-123";
    const certificatePEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+6ADAgECAgkAu7GVVfU7RAowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwP
c2t5Zmkuc29jaWFsIENBMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFow
GjEYMBYGA1UEAwwPdGVzdC5za3lmaS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3qywJtC5IxIDJRr4JSdBHBXBj6h+dK
FhnoHEQQzcIASJYqiwnjz7FZvlCrowIwADAKBggqhkjOPQQDAgNIADBFAiEA8Mwl
tOpA8eBWCGev2pG8LfrCNy6QZ1n7zP5cVL0cg5wCIF3rWGlFF4F3mOhHSQcKBJMx
p1J7dq0cL7a3AQ3sVoX9
-----END CERTIFICATE-----`;
    const privateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`;

    // Encrypt the private key
    const encryptedKey = PasswordEncryption.encrypt(privateKeyPEM, password);

    await adapter.saveCertificate(
      did,
      "endpoint",
      "test-client-456",
      certificatePEM,
      encryptedKey,
      true,
    );

    const retrieved = await adapter.getCertificate(
      did,
      "endpoint",
      "test-client-456",
    );
    expect(retrieved).toBeDefined();
    expect(retrieved?.certificatePEM).toBe(certificatePEM);
    expect(retrieved?.isEncrypted).toBe(true);
    expect(retrieved?.privateKeyPEM).toBeDefined();

    // Decrypt and verify
    const decryptedKey = PasswordEncryption.decrypt(
      retrieved!.privateKeyPEM!,
      password,
    );
    expect(decryptedKey).toBe(privateKeyPEM);
  });

  test("should list certificates for a DID", async () => {
    const did = "did:plc:test789";
    const certificatePEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+6ADAgECAgkAu7GVVfU7RAowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwP
c2t5Zmkuc29jaWFsIENBMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFow
GjEYMBYGA1UEAwwPdGVzdC5za3lmaS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3qywJtC5IxIDJRr4JSdBHBXBj6h+dK
FhnoHEQQzcIASJYqiwnjz7FZvlCrowIwADAKBggqhkjOPQQDAgNIADBFAiEA8Mwl
tOpA8eBWCGev2pG8LfrCNy6QZ1n7zP5cVL0cg5wCIF3rWGlFF4F3mOhHSQcKBJMx
p1J7dq0cL7a3AQ3sVoX9
-----END CERTIFICATE-----`;

    // Save multiple certificates
    await adapter.saveCertificate(did, "root", "root-001", certificatePEM);
    await adapter.saveCertificate(
      did,
      "endpoint",
      "client-001",
      certificatePEM,
      "private-key",
      false,
    );
    await adapter.saveCertificate(
      did,
      "endpoint",
      "client-002",
      certificatePEM,
    );

    const certs = await adapter.listCertificates(did);
    expect(certs).toHaveLength(3);

    const rootCert = certs.find((c) => c.type === "root");
    expect(rootCert).toBeDefined();
    expect(rootCert?.serialNumber).toBe("root-001");
    expect(rootCert?.hasPrivateKey).toBe(false);

    const clientWithKey = certs.find((c) => c.serialNumber === "client-001");
    expect(clientWithKey?.hasPrivateKey).toBe(true);

    const clientWithoutKey = certs.find((c) => c.serialNumber === "client-002");
    expect(clientWithoutKey?.hasPrivateKey).toBe(false);
  });

  test("should delete certificate", async () => {
    const did = "did:plc:testdelete";
    const certificatePEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+6ADAgECAgkAu7GVVfU7RAowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwP
c2t5Zmkuc29jaWFsIENBMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFow
GjEYMBYGA1UEAwwPdGVzdC5za3lmaS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3qywJtC5IxIDJRr4JSdBHBXBj6h+dK
FhnoHEQQzcIASJYqiwnjz7FZvlCrowIwADAKBggqhkjOPQQDAgNIADBFAiEA8Mwl
tOpA8eBWCGev2pG8LfrCNy6QZ1n7zP5cVL0cg5wCIF3rWGlFF4F3mOhHSQcKBJMx
p1J7dq0cL7a3AQ3sVoX9
-----END CERTIFICATE-----`;

    await adapter.saveCertificate(did, "root", "delete-me", certificatePEM);

    // Verify it exists
    let retrieved = await adapter.getCertificate(did, "root", "delete-me");
    expect(retrieved).toBeDefined();

    // Delete it
    await adapter.deleteCertificate(did, "root", "delete-me");

    // Verify it's gone
    retrieved = await adapter.getCertificate(did, "root", "delete-me");
    expect(retrieved).toBeNull();
  });

  test("PasswordEncryption should validate correct password", () => {
    const data = "sensitive data";
    const password = "correct-password";

    const encrypted = PasswordEncryption.encrypt(data, password);
    expect(PasswordEncryption.validate(encrypted, password)).toBe(true);
    expect(PasswordEncryption.validate(encrypted, "wrong-password")).toBe(
      false,
    );
  });

  test("PasswordEncryption should fail decryption with wrong password", () => {
    const data = "sensitive data";
    const password = "correct-password";

    const encrypted = PasswordEncryption.encrypt(data, password);

    expect(() => {
      PasswordEncryption.decrypt(encrypted, "wrong-password");
    }).toThrow("Failed to decrypt: Invalid password or corrupted data");
  });
});
