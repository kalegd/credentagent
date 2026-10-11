// The DSC-to-IACA certificate-trust step, shared by the mdoc wallet paths. This
// does not verify issuerAuth, value digests or device authentication (#14).
import { decode, Tag } from "cbor-x";
import { Registry, type CertificateTrustResult } from "trusted-issuer-registry";
import type { IssuerTrustOptions } from "../../types.js";

/** Resolved once per client; the registry owns its instance-local download cache. */
export type DscTrustResolver = (certificate?: string) => Promise<CertificateTrustResult>;

/** Internal data only — neither SDK metadata nor errors cross the response boundary. */
export type DscTrustCheck =
  | { result: CertificateTrustResult; error?: never }
  | { result?: never; error: string };

export type DscCertificate = { pem?: string; error?: never } | { pem?: never; error: string };

export function createIssuerTrustResolver(options?: IssuerTrustOptions): DscTrustResolver | undefined {
  if (!options) return undefined;
  const { trustLists = [], trustScope, ...registryOptions } = options;
  const registry = new Registry(registryOptions);
  const resolveOptions = { trustLists: [...trustLists], trustScope };
  return (certificate) => registry.resolveCertificateTrust(certificate, resolveOptions);
}

function headerValue(header: unknown, label: number): unknown {
  if (header instanceof Map) return header.get(label);
  if (header && typeof header === "object") return (header as Record<string, unknown>)[String(label)];
  return undefined;
}

/** Only the x5chain LEAF is input to the SDK. A presented chain never adds anchors. */
function dscPem(issuerAuth: unknown): string | undefined {
  const auth = issuerAuth instanceof Tag && issuerAuth.tag === 18 ? issuerAuth.value : issuerAuth;
  if (!Array.isArray(auth)) return undefined;
  const protectedBytes = auth[0];
  if (protectedBytes instanceof Uint8Array && protectedBytes.length > 0 && (protectedBytes[0] >> 5) !== 5) {
    throw new Error("COSE protected headers must encode a map");
  }
  const protectedHeaders = protectedBytes instanceof Uint8Array && protectedBytes.length > 0
    ? decode(protectedBytes)
    : undefined;
  const protectedChain = headerValue(protectedHeaders, 33);
  const unprotectedChain = headerValue(auth[1], 33);
  if (protectedChain !== undefined && unprotectedChain !== undefined) {
    throw new Error("x5chain occurs in both protected and unprotected headers");
  }
  const chain = protectedChain ?? unprotectedChain;
  if (chain === undefined || (Array.isArray(chain) && chain.length === 0)) return undefined;
  const leaf = Array.isArray(chain) ? chain[0] : chain;
  if (!(leaf instanceof Uint8Array)) throw new Error("x5chain must contain DER certificate bytes");
  if (leaf.length === 0) return undefined;
  const base64 = Buffer.from(leaf).toString("base64");
  return `-----BEGIN CERTIFICATE-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----`;
}

const errorMessage = (error: unknown): string => error instanceof Error ? error.message : "DSC trust resolution failed";

export function extractDscCertificate(issuerAuth: unknown): DscCertificate {
  try {
    return { pem: dscPem(issuerAuth) };
  } catch (error) {
    return { error: errorMessage(error) };
  }
}

/** Malformed certificates and SDK failures are internal data, not refusals. */
export async function checkDscTrust(certificate: DscCertificate, resolve?: DscTrustResolver): Promise<DscTrustCheck | undefined> {
  if (!resolve) return undefined;
  if (certificate.error !== undefined) return { error: certificate.error };
  try {
    return { result: await resolve(certificate.pem) };
  } catch (error) {
    return { error: errorMessage(error) };
  }
}
