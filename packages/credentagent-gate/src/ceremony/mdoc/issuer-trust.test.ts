import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Registry, UntrustedReason } from "trusted-issuer-registry";
import { checkDscTrust, extractDscCertificate, createIssuerTrustResolver, type DscTrustResolver } from "./issuer-trust.js";
import { verifyMdocDeviceResponse, verifyMdocVpToken } from "./verification.js";
import { ageDocument, cbor, deviceResponse, dscDer, dscPem, iacaPem, readerPem } from "./__fixtures__/issuer-trust.js";

const trustFromResponse = async (response: Uint8Array | string, issuerTrust?: DscTrustResolver) =>
  (await verifyMdocDeviceResponse(response, { issuerTrust })).documents.map((doc) => doc.checks.dscTrust);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-08T00:00:00Z"));
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network unavailable")));
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("preparatory DSC certificate trust", () => {
  it.each([
    { protected: false, chain: false }, { protected: false, chain: true },
    { protected: true, chain: false }, { protected: true, chain: true },
    { protected: true, chain: true, tag: true },
  ])("trusts the real demo DSC in x5chain %j, offline", async (options) => {
    const resolve = createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] });
    const checks = await trustFromResponse(deviceResponse([ageDocument(options)]), resolve);
    expect(checks[0]?.result?.trusted).toBe(true);
    expect(checks[0]?.result?.issuer?.certificates[0].data.trim()).toBe(iacaPem.trim());
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not promote a presented IACA into an anchor", async () => {
    const checks = await trustFromResponse(deviceResponse([ageDocument({ chain: true })]), createIssuerTrustResolver({}));
    expect(checks[0]?.result).toMatchObject({ trusted: false, untrustedReasons: [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND] });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects an unrelated configured issuer", async () => {
    const resolve = createIssuerTrustResolver({ trustedIssuerCertificates: [readerPem] });
    const checks = await trustFromResponse(deviceResponse([ageDocument()]), resolve);
    expect(checks[0]?.result?.trusted).toBe(false);
    expect(checks[0]?.result?.untrustedReasons).toContain(UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND);
  });

  it("checks the DSC signature, not merely its AKI", async () => {
    const tampered = Buffer.from(dscDer);
    tampered[tampered.length - 1] ^= 1;
    const resolve = createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] });
    const checks = await trustFromResponse(deviceResponse([ageDocument({ leaf: tampered })]), resolve);
    expect(checks[0]?.result?.trusted).toBe(false);
    expect(checks[0]?.result?.untrustedReasons).toContain(UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED);
  });

  it.each([
    ["2020-01-01", UntrustedReason.CERTIFICATE_NOT_YET_VALID, UntrustedReason.ISSUER_CERTIFICATE_NOT_YET_VALID],
    ["2080-01-01", UntrustedReason.CERTIFICATE_EXPIRED, UntrustedReason.ISSUER_CERTIFICATE_EXPIRED],
  ])("checks DSC and issuer validity at %s", async (now, leafReason, issuerReason) => {
    vi.setSystemTime(new Date(now));
    const checks = await trustFromResponse(deviceResponse([ageDocument()]), createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] }));
    expect(checks[0]?.result?.trusted).toBe(false);
    expect(checks[0]?.result?.untrustedReasons).toEqual(expect.arrayContaining([leafReason, issuerReason]));
  });

  it("keeps missing certificates and resolution errors as internal data", async () => {
    const resolve = createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] });
    const missing = { docType: "missing", issuerSigned: {} };
    const malformed = ageDocument({ leaf: Buffer.from([0xff]) });
    const checks = await trustFromResponse(deviceResponse([missing, malformed]), resolve);
    expect(checks[0]?.result).toEqual({ trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] });
    expect(checks[1]?.error).toEqual(expect.any(String));
    const failed = await trustFromResponse(deviceResponse([ageDocument()]), async () => { throw new Error("SDK failed"); });
    expect(failed).toEqual([{ error: "SDK failed" }]);
  });

  it.each([false, true])("passes empty x5chain to the SDK as missing (protected=%s)", async (protectedHeader) => {
    const resolve = vi.fn(createIssuerTrustResolver({})!);
    for (const chain of [[], Buffer.alloc(0), [Buffer.alloc(0)]]) {
      const headers = new Map([[33, chain]]);
      const doc = ageDocument();
      doc.issuerSigned.issuerAuth = [protectedHeader ? cbor(headers) : Buffer.alloc(0), protectedHeader ? new Map() : headers, null, Buffer.alloc(64)];
      const checks = await trustFromResponse(deviceResponse([doc]), resolve);
      expect(checks[0]).toEqual({ result: { trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] } });
    }
    expect(resolve).toHaveBeenCalledTimes(3);
    expect(resolve).toHaveBeenCalledWith(undefined);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("normalizes malformed headers and duplicate x5chain", async () => {
    const resolve = vi.fn().mockResolvedValue({ trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] });
    const doc = ageDocument();
    doc.issuerSigned.issuerAuth = [cbor(new Map([[33, dscDer]])), new Map([[33, dscDer]]), null, Buffer.alloc(64)];
    expect((await trustFromResponse(deviceResponse([doc]), resolve))[0]?.error).toContain("both protected and unprotected");
    doc.issuerSigned.issuerAuth = [Buffer.from([0xff]), new Map(), null, Buffer.alloc(64)];
    expect((await trustFromResponse(deviceResponse([doc]), resolve))[0]?.error).toEqual(expect.any(String));
    expect(resolve).not.toHaveBeenCalled();
  });

  it("checks every consumed document and matches vp_token's first-response selection", async () => {
    const resolve = vi.fn(createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] })!);
    const response = deviceResponse([ageDocument(), ageDocument({ protected: true })]).toString("base64url");
    const checks = await verifyMdocVpToken({ mdl: [response, "ignored"], other: response }, { issuerTrust: resolve });
    expect(checks.documents).toHaveLength(4);
    expect(checks.documents.every((doc) => doc.checks.dscTrust?.result?.trusted)).toBe(true);
    expect(resolve).toHaveBeenCalledTimes(4);
    expect((await verifyMdocVpToken([response], { issuerTrust: resolve })).documents).toHaveLength(2);
  });

  it("skips certificate resolution without configuration", async () => {
    expect(createIssuerTrustResolver()).toBeUndefined();
    expect(await checkDscTrust(extractDscCertificate(ageDocument().issuerSigned.issuerAuth))).toBeUndefined();
    const verification = await verifyMdocDeviceResponse(deviceResponse([ageDocument()]));
    expect(verification.documents[0].checks.dscTrust).toBeUndefined();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("SDK options and network policy", () => {
  it("forwards explicit trust lists and scope, retaining the configured list selection", async () => {
    const spy = vi.spyOn(Registry.prototype, "resolveCertificateTrust").mockResolvedValue({ trusted: false, untrustedReasons: [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND] });
    const lists: ("aamva_dts" | "uv")[] = ["aamva_dts"];
    const resolve = createIssuerTrustResolver({ trustLists: lists, trustScope: "government_issued_id" })!;
    lists.push("uv");
    await resolve(dscPem);
    expect(spy).toHaveBeenCalledWith(dscPem, { trustLists: ["aamva_dts"], trustScope: "government_issued_id" });
  });

  it("requires issuer scope only when configured, including for local anchors", async () => {
    const withoutScope = createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] })!;
    expect((await withoutScope(dscPem)).trusted).toBe(true);
    const withScope = createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem], trustScope: "document_signing" })!;
    expect((await withScope(dscPem)).untrustedReasons).toContain(UntrustedReason.ISSUER_MISSING_REQUIRED_TRUST_SCOPE);
    const scopedAnchor = createIssuerTrustResolver({ trustedIssuerCertificates: [{ data: iacaPem, trust_scopes: ["document_signing"] }], trustScope: "document_signing" })!;
    expect((await scopedAnchor(dscPem)).trusted).toBe(true);
  });

  it("queries the registry only for explicit lists and retains fetch failure reasons", async () => {
    const resolve = createIssuerTrustResolver({ trustLists: ["aamva_dts"] })!;
    const result = await resolve(dscPem);
    expect(result.trusted).toBe(false);
    expect(result.untrustedReasons).toContain(UntrustedReason.ISSUER_FETCH_FAILED);
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining("trusted-issuer-registry@0.2/issuers/x509_aki/"), expect.any(Object));
  });

  it.each(["skip", "best_effort", "required"] as const)("uses the configured CRL mode %s", async (revocationCheckMode) => {
    const resolve = createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem], trustLists: [], revocationCheckMode })!;
    const result = await resolve(dscPem);
    expect(result.trusted).toBe(revocationCheckMode !== "required");
    if (revocationCheckMode === "skip") expect(fetch).not.toHaveBeenCalled();
    else expect(fetch).toHaveBeenCalled();
    if (revocationCheckMode === "required") expect(result.untrustedReasons).toContain(UntrustedReason.REVOCATION_STATUS_UNDETERMINED);
  });

  it("forwards cache lifetime and disabling, without adding a verdict cache", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 404 }));
    const resolve = createIssuerTrustResolver({ trustLists: ["uv"], cacheTTL: 10 })!;
    await resolve(dscPem);
    await resolve(dscPem);
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.setSystemTime(new Date("2026-10-08T00:00:00.011Z"));
    await resolve(dscPem);
    expect(fetch).toHaveBeenCalledTimes(2);
    const uncached = createIssuerTrustResolver({ trustLists: ["uv"], cacheEnabled: false })!;
    await uncached(dscPem);
    await uncached(dscPem);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it("forwards the network timeout and captures the resulting fetch failure", async () => {
    let signal: AbortSignal | undefined;
    vi.mocked(fetch).mockImplementation(async (_url, init) => {
      signal = init?.signal as AbortSignal;
      return new Promise<Response>((_resolve, reject) => signal!.addEventListener("abort", () => reject(new Error("aborted"))));
    });
    const resolve = createIssuerTrustResolver({ trustLists: ["uv"], timeout: 5 })!;
    expect((await resolve(dscPem)).untrustedReasons).toContain(UntrustedReason.ISSUER_FETCH_FAILED);
    expect(signal?.aborted).toBe(true);
  });
});
