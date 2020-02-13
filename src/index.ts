import { BaseTransaction } from "@liskhq/lisk-transactions";
import {
  getKeys,
  hexToBuffer,
  bufferToHex,
  Keypair,
  hash
} from "@liskhq/lisk-cryptography";
import {
  Config as BaseConfig,
  Session as BaseSession,
  Round
} from "@futuretense/ed25519-musig";

export { Round };

export interface ExtendedLiskKeyPair extends Keypair {
  _seed: Buffer;
}

export class Config extends BaseConfig {
  public constructor(publicKeys: string[]) {
    const pbKeys: Buffer[] = publicKeys.map(pb => hexToBuffer(pb));
    super(pbKeys);
  }
  get publicKey() {
    return bufferToHex(super.publicKey);
  }
}

export class Session extends BaseSession {
  public constructor(
    config: Config,
    keyPair: ExtendedLiskKeyPair,
    transaction: BaseTransaction
  ) {
    const { _seed: seed } = keyPair;
    const txBytes = transaction.getBytes();
    super(config, seed, txBytes);
  }
}

export const generateKeyPairFromPassphrase = (
  passphrase: string
): ExtendedLiskKeyPair => {
  return {
    ...getKeys(passphrase),
    _seed: hash(passphrase, "utf8")
  };
};
