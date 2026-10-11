// The trust step must run, but neither a positive verdict nor a failure may
// change the existing response, receipt, or presence-only acceptance policy.
import { afterEach, describe, expect, it, vi } from "vitest";
import express from "express";
import request from "supertest";
import { decode } from "cbor-x";
import { Registry, UntrustedReason } from "trusted-issuer-registry";
import { CredentAgent } from "../../client.js";
import { age, payment, required, defineCredential, dcql, gate } from "../../credentials.js";
import { verifyCredentialPresentation } from "../credential-gate/verify.js";
import { verifyMdocPresentation } from "../credential-gate/mdoc-verify.js";
import { buildCredentialRequest } from "../credential-gate/request.js";
import { buildMdocRequestParts, sealMdocContext } from "./mdoc-iso.js";
import { openReaderContext } from "./readerContext.js";
import { mdocDocSpec } from "../credential-gate/doc-spec.js";
import { buildDcPaymentRequest } from "../dc-payment/request.js";
import { verifyDcPresentation } from "../dc-payment/verify.js";
import { createIssuerTrustResolver } from "./issuer-trust.js";
import { ageDocument, deviceResponse, encryptMdoc, encryptVpToken, iacaPem, paymentResponse } from "./__fixtures__/issuer-trust.js";
import type { CeremonySeams } from "../mount.js";

const SECRET = "stable-test-secret";
const ORIGIN = { rpID: "localhost", origin: "http://localhost:4000" };
const untrusted = { trusted: false as const, untrustedReasons: [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND] };
function resolverFor(mode: string) {
  if (mode === "trusted") return vi.fn(createIssuerTrustResolver({ trustedIssuerCertificates: [iacaPem] })!);
  return vi.fn(async () => {
    if (mode === "failed") throw new Error("SDK failed");
    return untrusted;
  });
}

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("wallet verification keeps its output contract", () => {
  it.each(["trusted", "untrusted", "failed"])("OpenID4VP checks every consumed document with %s trust without changing results", async (mode) => {
    const req = await buildCredentialRequest("age", ORIGIN, SECRET, { minimumAge: 21 });
    const dr = deviceResponse([ageDocument(), ageDocument({ protected: true })]).toString("base64url");
    const response = await encryptVpToken(req.request, { mdl: [dr], other: dr });
    const args = { kind: "age" as const, result: { data: { response } }, readerContextToken: req.readerContextToken, secret: SECRET };
    const baseline = await verifyCredentialPresentation(args);
    const issuerTrust = resolverFor(mode);
    const out = await verifyCredentialPresentation({ ...args, issuerTrust });
    expect(issuerTrust).toHaveBeenCalledTimes(4);
    if (mode === "trusted") expect((await issuerTrust.mock.results[0].value).trusted).toBe(true);
    expect(out).toEqual(baseline);
    expect(out.verified).toBe(true); // copied trusted DSC does not authenticate this forged mdoc
    expect(out.trust_level).toBe("presence-only-demo");
    expect(Object.keys(out).sort()).toEqual(["deviceResponse", "gates", "membershipNumber", "trust_level", "verified"]);
  });

  it.each(["trusted", "untrusted", "failed"])("org-iso-mdoc computes %s trust after HPKE decryption without changing results", async (mode) => {
    const parts = await buildMdocRequestParts(mdocDocSpec("age", 21), ORIGIN.origin);
    const mdocContextToken = await sealMdocContext({ readerPrivateJwk: parts.readerPrivateJwk, base64EncryptionInfo: parts.base64EncryptionInfo }, SECRET);
    const response = await encryptMdoc(parts.base64EncryptionInfo, ORIGIN.origin, deviceResponse([ageDocument(), ageDocument({ protected: true })]));
    const args = { kind: "age" as const, result: { data: { response } }, mdocContextToken, origin: ORIGIN, secret: SECRET };
    const baseline = await verifyMdocPresentation(args);
    const issuerTrust = resolverFor(mode);
    expect(await verifyMdocPresentation({ ...args, issuerTrust })).toEqual(baseline);
    expect(issuerTrust).toHaveBeenCalledTimes(2);
    expect(baseline.trust_level).toBe("presence-only-demo");
  });

  it("lets the SDK report a missing DSC for the iOS empty x5chain without changing results", async () => {
    const parts = await buildMdocRequestParts(mdocDocSpec("age", 21), ORIGIN.origin);
    const mdocContextToken = await sealMdocContext({ readerPrivateJwk: parts.readerPrivateJwk, base64EncryptionInfo: parts.base64EncryptionInfo }, SECRET);
    const doc = ageDocument();
    doc.issuerSigned.issuerAuth = [Buffer.alloc(0), new Map([[33, []]]), null, Buffer.alloc(64)];
    const response = await encryptMdoc(parts.base64EncryptionInfo, ORIGIN.origin, deviceResponse([doc]));
    const args = { kind: "age" as const, result: { data: { response } }, mdocContextToken, origin: ORIGIN, secret: SECRET };
    const baseline = await verifyMdocPresentation(args);
    const issuerTrust = vi.fn(createIssuerTrustResolver({})!);
    expect(await verifyMdocPresentation({ ...args, issuerTrust })).toEqual(baseline);
    expect(issuerTrust).toHaveBeenCalledTimes(1);
    expect(issuerTrust).toHaveBeenCalledWith(undefined);
    expect(await issuerTrust.mock.results[0].value).toEqual({ trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] });
    expect(baseline.verified).toBe(true);
    expect(baseline.trust_level).toBe("presence-only-demo");
  });

  it("does not let trusted certificates satisfy a false claim, including custom credentials", async () => {
    const req = await buildCredentialRequest("age", ORIGIN, SECRET, { minimumAge: 21 });
    const response = await encryptVpToken(req.request, { mdl: deviceResponse([ageDocument({ value: false })]).toString("base64url") });
    const issuerTrust = resolverFor("trusted");
    const args = { kind: "age" as const, result: { data: { response } }, readerContextToken: req.readerContextToken, secret: SECRET, issuerTrust };
    expect((await verifyCredentialPresentation(args)).verified).toBe(false);
    const credential = defineCredential({
      id: "custom-age",
      request: dcql({ docType: "org.iso.18013.5.1.mDL", claims: ["age_over_21"] }),
      verify: (c) => c.age_over_21 === true,
      effect: gate(),
      ui: { label: "Age", action: "Present" },
    });
    expect((await verifyCredentialPresentation({ ...args, credential })).verified).toBe(false);
    expect(issuerTrust).toHaveBeenCalledTimes(2);
  });

  it.each(["trusted", "untrusted", "failed"])("DC payment computes %s trust without changing the mandate or gates", async (mode) => {
    const order = {
      id: "ORD-P", lines: [{ id: "coffee", name: "Coffee", quantity: 1, unitPrice: 18, lineTotal: 18, currency: "USD" }],
      subtotal: 18, discount: 0, total: 18, currency: "USD", itemCount: 1,
    };
    const req = await buildDcPaymentRequest(order, ORIGIN, SECRET);
    const encoded = paymentResponse(req.transaction_data[0]);
    const parsed = decode(encoded) as { documents: unknown[] };
    const response = await encryptVpToken(req.request, { dpc: deviceResponse([...parsed.documents, ageDocument()]).toString("base64url") });
    const args = { order, origin: ORIGIN, result: { data: { response } }, readerContextToken: req.readerContextToken, secret: SECRET };
    const baseline = await verifyDcPresentation(args);
    const issuerTrust = resolverFor(mode);
    const out = await verifyDcPresentation({ ...args, issuerTrust });
    expect(issuerTrust).toHaveBeenCalledTimes(2);
    expect(out.gates).toEqual(baseline.gates);
    expect(out.gates.every((g) => g.pass)).toBe(true);
    // These are already generated afresh per verification, unrelated to certificate trust.
    expect({ ...out.mandate, id: baseline.mandate.id, issuedAt: baseline.mandate.issuedAt, expiresAt: baseline.mandate.expiresAt }).toEqual(baseline.mandate);
    expect(Object.keys(out).sort()).toEqual(["gates", "mandate"]);
    expect(out.mandate.trust_level).toBe("presence-only-demo");
  });

  it("seals the original origin for both OpenID4VP verification paths", async () => {
    const credential = await buildCredentialRequest("age", ORIGIN, SECRET);
    const payment = await buildDcPaymentRequest({ id: "ORD-CONTEXT", lines: [], subtotal: 0, discount: 0, total: 0, currency: "USD", itemCount: 0 }, ORIGIN, SECRET);
    expect((await openReaderContext(credential.readerContextToken, SECRET)).origin).toBe(ORIGIN.origin);
    expect((await openReaderContext(payment.readerContextToken, SECRET)).origin).toBe(ORIGIN.origin);
  });
});

describe("configure once across client entry points", () => {
  function client() {
    return new CredentAgent({
      walletOrigin: ORIGIN.origin,
      gateSecret: SECRET,
      catalog: { wine: { price: 21, minAge: 21 } },
      issuerTrust: {},
    });
  }
  const seams = (ca: CredentAgent): CeremonySeams => ({
    verificationStore: ca.store, orderStore: { read: () => null }, catalog: { createOrder: () => { throw new Error("unused"); } },
    completion: async () => ({ completed: false }), signingKey: SECRET,
  });

  it("shares one resolver through explicit mount, composed mount, orders.serve and grants", () => {
    const ca = client();
    const explicit = { locals: {} as Record<string, unknown> };
    ca.mount(explicit, seams(ca));
    const issuerTrust = (explicit.locals.credentagent as CeremonySeams).issuerTrust;
    const composed = { locals: { credentagent: seams(ca) } };
    ca.mount(composed);
    expect(composed.locals.credentagent.issuerTrust).toBe(issuerTrust);
    const ordersApp = express();
    ca.orders.serve(ordersApp as never);
    expect((ordersApp.locals.credentagent as CeremonySeams).issuerTrust).toBe(issuerTrust);
    expect(ca.grants.railConfig.issuerTrust).toBe(issuerTrust);
    expect(client().grants.railConfig.issuerTrust).not.toBe(issuerTrust);
    expect(new CredentAgent().grants.railConfig.issuerTrust).toBeUndefined();
  });

  it.each(["openid4vp-v1-signed", "org-iso-mdoc"])("orders and grant credential HTTP routes invoke the SDK on %s and keep responses unchanged", async (protocol) => {
    const spy = vi.spyOn(Registry.prototype, "resolveCertificateTrust").mockRejectedValue(new Error("SDK unavailable"));
    const ca = client();
    const app = express();
    app.use(express.json());
    ca.orders.serve(app as never);
    ca.grants.serve(app as never);
    const order = { id: "ORD-TRUST", total: 2100, currency: "USD", lines: [{ id: "wine", quantity: 1, unitPrice: 2100, minimumAge: 21 }] };
    const created = await ca.orders.create({ order, policy: [required(age.over(21))] });
    const grant = await ca.grants.create({ merchant: "utopia", budget: 100, perSpend: 30, allow: { skus: ["wine"] } });
    const endpoints = [
      { base: "/credentagent/credential", query: { cred: "age", order: created.id }, body: { cred: "age", order: created.id } },
      { base: `/credentagent/grants/${grant.id}/age`, query: {}, body: {} },
    ];
    for (const endpoint of endpoints) {
      const req = (await request(app).get(`${endpoint.base}/request`).query(endpoint.query).set("Host", "localhost:4000").expect(200)).body;
      const walletRequest = req.requests.find((r: { protocol: string }) => r.protocol === protocol);
      const dr = deviceResponse([ageDocument()]);
      const response = protocol === "org-iso-mdoc"
        ? await encryptMdoc(walletRequest.data.encryptionInfo, ORIGIN.origin, dr)
        : await encryptVpToken(walletRequest.data.request, { mdl: dr.toString("base64url") });
      const res = await request(app).post(`${endpoint.base}/verify`).set("Host", "localhost:4000").send({
        ...endpoint.body, readerContextToken: req.readerContextToken, mdocContextToken: req.mdocContextToken,
        result: { protocol, data: { response } },
      }).expect(200);
      expect(res.body).toEqual({
        verified: true,
        membershipNumber: null,
        gates: [{ gate: "Age over 21", pass: true, detail: "age_over_21 disclosed true" }],
        trust_level: "presence-only-demo",
      });
    }
    expect(spy).toHaveBeenCalledTimes(2);
    // The recorded proof still contains only the existing fields and checks.
    const record = await ca.store.read(created.id);
    expect(record?.ageVerified).toBe(true);
    expect(record?.proofs?.[0].checks).toHaveLength(1);
    expect(record?.proofs?.[0]).not.toHaveProperty("dscTrust");
    expect((await ca.grants.retrieve(grant.id))?.ageProof).toBeDefined();
    spy.mockClear();
    await request(app).post("/credentagent/credential/verify").send({ cred: "age", order: created.id, claims: { age_over_21: true } }).expect(200);
    await request(app).post(`/credentagent/grants/${grant.id}/age/verify`).send({ claims: { age_over_21: true } }).expect(200);
    expect(spy).not.toHaveBeenCalled();
  });

  it("the DC payment HTTP route checks trust without changing completion or receipts", async () => {
    const spy = vi.spyOn(Registry.prototype, "resolveCertificateTrust").mockRejectedValue(new Error("SDK unavailable"));
    const ca = client();
    const app = express();
    app.use(express.json());
    ca.orders.serve(app as never);
    const created = await ca.orders.create({
      order: { id: "ORD-COFFEE", total: 1800, currency: "USD", lines: [{ id: "coffee", quantity: 1, unitPrice: 1800 }] },
      policy: [required(payment.in("usd"))],
    });
    const req = (await request(app).get("/credentagent/dc-payment/request").query({ order: created.id }).set("Host", "localhost:4000").expect(200)).body;
    const response = await encryptVpToken(req.request, { dpc: paymentResponse(req.transaction_data[0]).toString("base64url") });
    const res = await request(app).post("/credentagent/dc-payment/verify").set("Host", "localhost:4000").send({
      order: created.id, readerContextToken: req.readerContextToken,
      result: { protocol: "openid4vp-v1-signed", data: { response } },
    }).expect(200);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(res.body.completed).toBe(true);
    expect(res.body.gates).toHaveLength(4);
    expect(res.body.gates.every((g: { pass: boolean }) => g.pass)).toBe(true);
    expect(res.body.mandate.trust_level).toBe("presence-only-demo");
    expect(res.body).not.toHaveProperty("dscTrust");
    expect(res.body.proofsHtml).toContain("presence-only-demo");
    spy.mockClear();
    await request(app).post("/credentagent/dc-payment/verify").send({
      order: created.id, amount: 18, claims: { payment_instrument_id: "pi-1", expiry_date: "2032-09-01" },
    }).expect(200);
    expect(spy).not.toHaveBeenCalled();
  });
});
