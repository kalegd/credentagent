// Shared per-document checks. Only DSC certificate trust is implemented (#14);
// document authentication explicitly reports its pending status, never success.
import type { MdocDocument, DisclosedEntry } from "./mdoc.js";
import {
  extractDscCertificate,
  checkDscTrust,
  type DscCertificate,
  type DscTrustCheck,
  type DscTrustResolver,
} from "./issuer-trust.js";

export interface MdocVerificationContext {
  issuerTrust?: DscTrustResolver;
  /** Expected transcript from the reader context, never supplied by the document. */
  sessionTranscript?: Uint8Array;
}

export interface PendingMdocCheck {
  status: "not-implemented";
}

export interface ParsedMdocDocument {
  /** Original auth blocks and tagged item bytes, kept separate from sanitized claims. */
  document: MdocDocument;
  queryId: string;
  documentIndex: number;
  claims: DisclosedEntry["claims"];
}

export interface MdocDocumentVerification {
  queryId: string;
  documentIndex: number;
  docType?: string;
  claims: DisclosedEntry["claims"];
  checks: {
    documentAuthentication: PendingMdocCheck;
    dscTrust?: DscTrustCheck;
  };
}

async function verifyDocumentAuthentication(
  _document: MdocDocument,
  _certificate: DscCertificate,
  _sessionTranscript?: Uint8Array,
): Promise<PendingMdocCheck> {
  // TODO(#14): verify issuerAuth with the DSC, disclosed-value digests, MSO structure,
  // docType and validity, then DeviceAuth with the authenticated MSO key and expected
  // transcript. Together these establish device-signed; DSC trust is a separate check.
  return { status: "not-implemented" };
}

export async function verifyMdocDocument(
  { document, claims, queryId, documentIndex }: ParsedMdocDocument,
  context: MdocVerificationContext,
): Promise<MdocDocumentVerification> {
  const certificate = extractDscCertificate(document.issuerSigned?.issuerAuth);
  return {
    queryId, documentIndex, docType: document.docType, claims,
    checks: {
      documentAuthentication: await verifyDocumentAuthentication(document, certificate, context.sessionTranscript),
      dscTrust: await checkDscTrust(certificate, context.issuerTrust),
    },
  };
}
