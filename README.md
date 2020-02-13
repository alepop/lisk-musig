# @alepop/lisk-musig

Three round m-of-m key aggregation for Lisk using the MuSig signature scheme

## Installation

`npm install @alepop/lisk-musig`

## Usage

```javascript
import * as musig from "@alepop/lisk-musig";
import { TransferTransaction } from "@liskhq/lisk-transactions";
import { verifyData, bufferToHex } from "@liskhq/lisk-cryptography";

const keys1 = musig.generateKeyPairFromPassphrase(/* mnemonica */);
const keys2 = musig.generateKeyPairFromPassphrase(/* mnemonica */);

const config = new musig.Config([keys1.publicKey, keys2.publicKey]);

const aggregatePubkicKey = config.publicKey;

const tx = new TransferTransaction({
  recipientId: "18160565574430594874L",
  amount: "1000",
  networkIdentifier:
    "e48feb88db5b5cf5ad71d93cdcd1d879b6d5ed187a36b0002cc34e0ef9883255",
  senderPublicKey: aggregatePubkicKey
});

const session1 = new musig.Session(config, keys1, tx);
const session2 = new musig.Session(config, keys2, tx);

/* round 1 */
const c1 = session1.getLocalCommitment();
const c2 = session2.getLocalCommitment();
session1.setRemoteCommitment(...c2);
session2.setRemoteCommitment(...c1);

/* roun 2 */
const n1 = session1.getLocalNonce();
const n2 = session2.getLocalNonce();
session1.setRemoteNonce(...n2);
session2.setRemoteNonce(...n1);

/* round 3 */
const s1 = session1.getLocalSignature();
const s2 = session2.getLocalSignature();
session1.setRemoteSignature(...s2);
session2.setRemoteSignature(...s1);

/* Verify the signature */
const signature = session1.aggregateSignature;
const isValid = verifyData(
  tx.getBytes(),
  bufferToHex(signature),
  aggregatePubkicKey
);
```

## References

[@futuretense/ed25519-musig](https://github.com/future-tense/ed25519-musig)
