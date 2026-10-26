// A software passkey for tests: makes real ES256 registrations and assertions
// the way Ben's phone would, so the desk's checks run unmodified.

import { isoCBOR } from "@simplewebauthn/server/helpers";
import { b64url, fromB64url } from "../src/desk.ts";

const enc = new TextEncoder();

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

// WebCrypto signs ECDSA as raw r||s; WebAuthn carries it DER-encoded.
function derSignature(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.slice(i);
    return v[0] & 0x80 ? [0x02, v.length + 1, 0, ...v] : [0x02, v.length, ...v];
  };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}

export class SoftKey {
  id = b64url(crypto.getRandomValues(new Uint8Array(16)));
  counter = 0;
  private pair: CryptoKeyPair;
  private constructor(pair: CryptoKeyPair) {
    this.pair = pair;
  }

  static async create(): Promise<SoftKey> {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    return new SoftKey(pair as CryptoKeyPair);
  }

  private async authData(rpID: string, flags: number, attested?: Uint8Array): Promise<Uint8Array> {
    const count = new Uint8Array(4);
    new DataView(count.buffer).setUint32(0, this.counter);
    return new Uint8Array([...(await sha256(enc.encode(rpID))), flags, ...count, ...(attested ?? [])]);
  }

  async register(options: { challenge: string; rp: { id?: string } }, origin: string) {
    const jwk = (await crypto.subtle.exportKey("jwk", this.pair.publicKey)) as JsonWebKey;
    const cose = isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, fromB64url(jwk.x!)],
        [-3, fromB64url(jwk.y!)],
      ]),
    );
    const credId = fromB64url(this.id);
    const attested = new Uint8Array([...new Uint8Array(16), credId.length >> 8, credId.length & 255, ...credId, ...cose]);
    const authData = await this.authData(options.rp.id!, 0x45, attested); // UP | UV | AT
    const attestationObject = isoCBOR.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]) as never);
    const clientDataJSON = enc.encode(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin }));
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key" as const,
      clientExtensionResults: {},
      response: { clientDataJSON: b64url(clientDataJSON), attestationObject: b64url(attestationObject) },
    };
  }

  async assert(challenge: string, rpID: string, origin: string, { userVerified = true } = {}) {
    this.counter++;
    const authData = await this.authData(rpID, userVerified ? 0x05 : 0x01);
    const clientDataJSON = enc.encode(JSON.stringify({ type: "webauthn.get", challenge, origin }));
    const signed = new Uint8Array([...authData, ...(await sha256(clientDataJSON))]);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.pair.privateKey, signed));
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key" as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(derSignature(raw)),
      },
    };
  }
}
