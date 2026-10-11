import { describe, expect, it, vi } from "vitest";
import { UntrustedReason } from "trusted-issuer-registry";
import { decodeVpToken } from "./mdoc.js";
import { verifyMdocDeviceResponse, verifyMdocVpToken } from "./verification.js";
import { createIssuerTrustResolver } from "./issuer-trust.js";
import { buildOpenId4VpSessionTranscript } from "./mdoc-iso.js";
import { ageDocument, cbor, deviceResponse, iacaPem } from "./__fixtures__/issuer-trust.js";

describe("shared mdoc verification pipeline", () => {
  it("keeps document authentication pending even when a copied DSC is trusted", async () => {
    const input = deviceResponse([ageDocument()]);
    const verification = await verifyMdocDeviceResponse(input, {
      issuerTrust: createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] }),
      sessionTranscript: cbor([null, null, ["test"]]),
    });
    const checks = verification.documents[0].checks;
    expect(checks.dscTrust?.result?.trusted).toBe(true);
    expect(checks.documentAuthentication).toEqual({ status: "not-implemented" });
    expect(verification.disclosed).toEqual(decodeVpToken({ mdoc: input.toString("base64url") }));
  });

  it("keeps same-doctype documents, claims and trust results correlated", async () => {
    const resolve = vi.fn(createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] })!);
    const document = ageDocument({ value: false });
    const missing = { ...document, issuerSigned: { nameSpaces: document.issuerSigned.nameSpaces } };
    const response = deviceResponse([ageDocument(), missing]).toString("base64url");
    const token = { first: [response, "ignored"], second: response };
    const verification = await verifyMdocVpToken(token, { issuerTrust: resolve });
    expect(verification.documents.map(({ queryId, documentIndex, docType }) => ({ queryId, documentIndex, docType }))).toEqual([
      { queryId: "first", documentIndex: 0, docType: "org.iso.18013.5.1.mDL" },
      { queryId: "first", documentIndex: 1, docType: "org.iso.18013.5.1.mDL" },
      { queryId: "second", documentIndex: 0, docType: "org.iso.18013.5.1.mDL" },
      { queryId: "second", documentIndex: 1, docType: "org.iso.18013.5.1.mDL" },
    ]);
    expect(verification.documents.map((doc) => doc.claims[0].value)).toEqual([true, false, true, false]);
    expect(verification.documents[0].checks.dscTrust?.result?.trusted).toBe(true);
    expect(verification.documents[1].checks.dscTrust?.result).toEqual({ trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] });
    expect(verification.disclosed).toEqual(decodeVpToken(token));
    expect(resolve).toHaveBeenCalledTimes(4);
  });

  it("finishes parsing all consumed responses before invoking the registry", async () => {
    const resolve = vi.fn().mockResolvedValue({ trusted: false, untrustedReasons: [] });
    const valid = deviceResponse([ageDocument()]).toString("base64url");
    const document = ageDocument();
    const broken = {
      ...document,
      issuerSigned: { ...document.issuerSigned, nameSpaces: { test: [Buffer.from([0xa1])] } },
    };
    const token = { first: valid, second: deviceResponse([broken]).toString("base64url") };
    await expect(verifyMdocVpToken(token, { issuerTrust: resolve })).rejects.toThrow();
    await expect(verifyMdocDeviceResponse(Buffer.from([0xa1]), { issuerTrust: resolve })).rejects.toThrow();
    expect(resolve).not.toHaveBeenCalled();
  });

  it("retains malformed certificate errors beside the correct document without refusing disclosures", async () => {
    const resolve = vi.fn().mockResolvedValue({ trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] });
    const malformed = ageDocument();
    malformed.issuerSigned.issuerAuth = [Buffer.alloc(0), new Map([[33, "not certificate bytes"]]), null, Buffer.alloc(64)];
    const verification = await verifyMdocDeviceResponse(deviceResponse([malformed, ageDocument()]), { issuerTrust: resolve });
    expect(verification.documents[0].checks.dscTrust).toEqual({ error: "x5chain must contain DER certificate bytes" });
    expect(verification.documents[1].checks.dscTrust?.result).toBeDefined();
    expect(verification.disclosed[0].claims).toHaveLength(2);
    expect(resolve).toHaveBeenCalledTimes(1);
  });

  it("keeps empty responses and missing binding from establishing any authentication", async () => {
    expect(await verifyMdocVpToken(undefined)).toEqual({ disclosed: [], documents: [] });
    const empty = deviceResponse([]).toString("base64url");
    const verification = await verifyMdocVpToken({ empty });
    expect(verification.documents).toEqual([]);
    expect(verification.disclosed).toEqual(decodeVpToken({ empty }));
    const withoutBinding = await verifyMdocDeviceResponse(deviceResponse([ageDocument()]));
    expect(withoutBinding.documents[0].checks.documentAuthentication.status).toBe("not-implemented");
    expect(withoutBinding.documents[0].checks.dscTrust).toBeUndefined();
  });
});

describe("expected OpenID4VP session transcript", () => {
  it("matches the published OpenID4VP 1.0 B.2.6.2 example", async () => {
    const transcript = await buildOpenId4VpSessionTranscript({
      origin: "https://example.com",
      nonce: "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
      transactionDataB64: "",
      ecdhPrivateJwk: {
        kty: "EC", crv: "P-256",
        x: "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
        y: "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
      },
    });
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-invocation-via-the-digital-c
    expect(Buffer.from(transcript!).toString("hex")).toBe(
      "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a",
    );
  });

  it("leaves older reader contexts without an expected transcript", async () => {
    expect(await buildOpenId4VpSessionTranscript({ ecdhPrivateJwk: { kty: "EC" }, transactionDataB64: "", nonce: "nonce" })).toBeUndefined();
  });
});
