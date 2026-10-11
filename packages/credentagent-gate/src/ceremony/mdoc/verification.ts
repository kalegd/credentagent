// Protocol adapters decrypt first; both then use this shared mdoc pipeline.
import {
  decodeDeviceResponse,
  deviceResponsesFromVpToken,
  disclosedFromDocument,
  type DeviceResponse,
  type DisclosedEntry,
} from "./mdoc.js";
import {
  verifyMdocDocument,
  type MdocDocumentVerification,
  type MdocVerificationContext,
} from "./document-verification.js";

export interface MdocVerification {
  disclosed: DisclosedEntry[];
  documents: MdocDocumentVerification[];
}

function parseMdocDeviceResponse(input: Uint8Array | string, queryId: string) {
  const response = decodeDeviceResponse(input);
  const documents = (response.documents ?? []).map((document, documentIndex) => ({
    document, queryId, documentIndex, claims: disclosedFromDocument(document),
  }));
  return { response, queryId, documents };
}

async function verifyParsedDeviceResponse(
  { response, queryId, documents: parsed }: ReturnType<typeof parseMdocDeviceResponse>,
  context: MdocVerificationContext,
): Promise<MdocVerification & { response: DeviceResponse }> {
  const documents = await Promise.all(parsed.map((document) => verifyMdocDocument(document, context)));
  const disclosed = [{
    id: queryId, format: "mso_mdoc", type: documents.at(-1)?.docType,
    claims: documents.flatMap((document) => document.claims),
  }];
  return { response, disclosed, documents };
}

/** Parse once; preserve per-document results alongside today's disclosure shape. */
export async function verifyMdocDeviceResponse(
  input: Uint8Array | string,
  context: MdocVerificationContext = {},
  queryId = "mdoc",
): Promise<MdocVerification & { response: DeviceResponse }> {
  return verifyParsedDeviceResponse(parseMdocDeviceResponse(input, queryId), context);
}

export async function verifyMdocVpToken(vpToken: unknown, context: MdocVerificationContext = {}): Promise<MdocVerification> {
  // Finish parsing every consumed response before running certificate resolution.
  const parsed = deviceResponsesFromVpToken(vpToken).map(([queryId, response]) => parseMdocDeviceResponse(response, queryId));
  const results = await Promise.all(parsed.map((response) => verifyParsedDeviceResponse(response, context)));
  return {
    disclosed: results.flatMap((result) => result.disclosed),
    documents: results.flatMap((result) => result.documents),
  };
}
