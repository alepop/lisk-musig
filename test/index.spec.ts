import { Session, Config, generateKeyPairFromPassphrase } from "../src";
import { verifyData, bufferToHex } from "@liskhq/lisk-cryptography";
import { TransferTransaction } from "@liskhq/lisk-transactions";

describe("2-of-2 key aggregation", () => {
  const keys1 = generateKeyPairFromPassphrase("123");
  const keys2 = generateKeyPairFromPassphrase("456");

  const config = new Config([keys1.publicKey, keys2.publicKey]);

  const tx = new TransferTransaction({
    recipientId: "18160565574430594874L",
    amount: "1000",
    networkIdentifier:
      "e48feb88db5b5cf5ad71d93cdcd1d879b6d5ed187a36b0002cc34e0ef9883255",
    senderPublicKey: config.publicKey
  });

  const session1 = new Session(config, keys1, tx);
  const session2 = new Session(config, keys2, tx);

  //  signing round #1: generate random nonces, and submit commitments
  const c1 = session1.getLocalCommitment();
  const c2 = session2.getLocalCommitment();

  session1.setRemoteCommitment(...c2);
  session2.setRemoteCommitment(...c1);

  //  signing round #2: submit nonces
  const n1 = session1.getLocalNonce();
  const n2 = session2.getLocalNonce();

  session1.setRemoteNonce(...n2);
  session2.setRemoteNonce(...n1);

  //  signing round #3: sign message and submit signature for aggregation
  const s1 = session1.getLocalSignature();
  const s2 = session2.getLocalSignature();

  session1.setRemoteSignature(...s2);
  session2.setRemoteSignature(...s1);

  test("aggregate signature should be equal in each party", () => {
    const signature1 = session1.aggregateSignature;
    const signature2 = session2.aggregateSignature;
    expect(signature1).toEqual(signature2);
  });

  test("signature should be correct", () => {
    const signature = session1.aggregateSignature;
    expect(
      verifyData(tx.getBytes(), bufferToHex(signature), config.publicKey)
    ).toBeTruthy();
  });
});

describe("3-of-3 key aggregation", () => {
  const keys1 = generateKeyPairFromPassphrase("123");
  const keys2 = generateKeyPairFromPassphrase("456");
  const keys3 = generateKeyPairFromPassphrase("789");

  const config = new Config([
    keys1.publicKey,
    keys2.publicKey,
    keys3.publicKey
  ]);

  const tx = new TransferTransaction({
    recipientId: "18160565574430594874L",
    amount: "1000",
    networkIdentifier:
      "e48feb88db5b5cf5ad71d93cdcd1d879b6d5ed187a36b0002cc34e0ef9883255",
    senderPublicKey: config.publicKey
  });

  const session1 = new Session(config, keys1, tx);
  const session2 = new Session(config, keys2, tx);
  const session3 = new Session(config, keys3, tx);
  //  signing round #1: generate random nonces, and submit commitments
  const c1 = session1.getLocalCommitment();
  const c2 = session2.getLocalCommitment();
  const c3 = session3.getLocalCommitment();

  session1.setRemoteCommitment(...c2);
  session1.setRemoteCommitment(...c3);

  session2.setRemoteCommitment(...c1);
  session2.setRemoteCommitment(...c3);

  session3.setRemoteCommitment(...c1);
  session3.setRemoteCommitment(...c2);

  //  signing round #2: submit nonces
  const n1 = session1.getLocalNonce();
  const n2 = session2.getLocalNonce();
  const n3 = session3.getLocalNonce();

  session1.setRemoteNonce(...n2);
  session1.setRemoteNonce(...n3);

  session2.setRemoteNonce(...n1);
  session2.setRemoteNonce(...n3);

  session3.setRemoteNonce(...n1);
  session3.setRemoteNonce(...n2);

  //  signing round #3: sign message and submit signature for aggregation
  const s1 = session1.getLocalSignature();
  const s2 = session2.getLocalSignature();
  const s3 = session3.getLocalSignature();

  session1.setRemoteSignature(...s2);
  session1.setRemoteSignature(...s3);

  session2.setRemoteSignature(...s1);
  session2.setRemoteSignature(...s3);

  session3.setRemoteSignature(...s1);
  session3.setRemoteSignature(...s2);
  test("aggregate signature should be equal in each party", () => {
    const signature1 = session1.aggregateSignature;
    const signature2 = session2.aggregateSignature;
    const signature3 = session3.aggregateSignature;
    expect(signature1).toEqual(signature2);
    expect(signature2).toEqual(signature3);
  });

  test("signature should be correct", () => {
    const signature = session1.aggregateSignature;
    expect(
      verifyData(tx.getBytes(), bufferToHex(signature), config.publicKey)
    ).toBeTruthy();
  });
});
