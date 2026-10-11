// Public demo PKI plus synthetic mdocs: the certificates are real, the mdoc
// signatures are deliberately forged to pin the presence-only boundary.
import { readFileSync } from "node:fs";
import { createHash, X509Certificate } from "node:crypto";
import { Encoder, Tag, decode } from "cbor-x";
import * as jose from "jose";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { buildSessionTranscript } from "../mdoc-iso.js";

const cert = (name: string): string => readFileSync(new URL(`../../../../../../tools/demo-pki/certs/${name}`, import.meta.url), "utf8");
export const iacaPem = cert("iaca-cert.pem");
export const dscPem = cert("ds-cert.pem");
export const readerPem = cert("reader-cert.pem");
export const dscDer = new X509Certificate(dscPem).raw;
export const iacaDer = new X509Certificate(iacaPem).raw;
// cbor-x supports useTag259ForMaps at runtime; its Options declaration omits it.
const encoderOptions = { useRecords: false, variableMapSize: true, useTag259ForMaps: false };
const encoder = new Encoder(encoderOptions);
export const cbor = (value: unknown): Buffer => encoder.encode(value);

export function ageDocument(options: { leaf?: Uint8Array; protected?: boolean; chain?: boolean; value?: boolean; tag?: boolean } = {}) {
  const leaf = options.leaf ?? dscDer;
  const chain = options.chain ? [leaf, iacaDer] : leaf;
  const headers = new Map<number, unknown>([[33, chain]]);
  const auth = [options.protected ? cbor(headers) : Buffer.alloc(0), options.protected ? new Map() : headers, null, Buffer.alloc(64)];
  return {
    docType: "org.iso.18013.5.1.mDL",
    issuerSigned: {
      nameSpaces: { "org.iso.18013.5.1": [new Tag(cbor({
        digestID: 0, random: Buffer.alloc(16), elementIdentifier: "age_over_21", elementValue: options.value ?? true,
      }), 24)] },
      issuerAuth: options.tag ? new Tag(auth, 18) : auth,
    },
  };
}

export const deviceResponse = (documents: unknown[]): Buffer => cbor({ version: "1.0", documents, status: 0 });

export function paymentResponse(transactionData: string): Buffer {
  const doc = ageDocument();
  const ns = "org.multipaz.payment.sca.1";
  const instrument = { issuer_name: "Demo Bank", payment_instrument_id: "pi-1", expiry_date: "2032-09-01" };
  return deviceResponse([{
    ...doc, docType: ns,
    issuerSigned: {
      ...doc.issuerSigned,
      nameSpaces: {
        [ns]: Object.entries(instrument).map(([elementIdentifier, elementValue], digestID) =>
          new Tag(cbor({ digestID, random: Buffer.alloc(16), elementIdentifier, elementValue }), 24)),
      },
    },
    deviceSigned: {
      nameSpaces: new Tag(cbor({ "urn:eudi:sca:payment:1": { transaction_data_hash: createHash("sha256").update(transactionData).digest() } }), 24),
      deviceAuth: { deviceSignature: [Buffer.alloc(0), {}, null, Buffer.alloc(64)] },
    },
  }]);
}

export async function encryptVpToken(requestJwt: string, vpToken: unknown): Promise<string> {
  const payload = jose.decodeJwt(requestJwt) as { client_metadata: { jwks: { keys: jose.JWK[] } } };
  const key = await jose.importJWK(payload.client_metadata.jwks.keys[0], "ECDH-ES");
  return new jose.CompactEncrypt(Buffer.from(JSON.stringify({ vp_token: vpToken })))
    .setProtectedHeader({ alg: "ECDH-ES", enc: "A128GCM" }).encrypt(key);
}

/** Wallet encryption uses only the public recipient key in EncryptionInfo. */
export async function encryptMdoc(encryptionInfo: string, origin: string, response: Uint8Array): Promise<string> {
  const [, info] = decode(Buffer.from(encryptionInfo, "base64url")) as [string, { recipientPublicKey: Map<number, unknown> | Record<string, unknown> }];
  const key = info.recipientPublicKey;
  const coordinate = (label: number) => key instanceof Map ? key.get(label) : key[String(label)];
  const jwk = {
    kty: "EC", crv: "P-256",
    x: Buffer.from(coordinate(-2) as Uint8Array).toString("base64url"),
    y: Buffer.from(coordinate(-3) as Uint8Array).toString("base64url"),
  };
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  const recipientPublicKey = await suite.kem.importKey("jwk", jwk, true);
  const toAB = (bytes: Uint8Array) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const sender = await suite.createSenderContext({ recipientPublicKey, info: toAB(buildSessionTranscript(encryptionInfo, origin)) });
  const cipherText = new Uint8Array(await sender.seal(toAB(response)));
  return cbor(["dcapi", { enc: Buffer.from(new Uint8Array(sender.enc)), cipherText: Buffer.from(cipherText) }]).toString("base64url");
}
