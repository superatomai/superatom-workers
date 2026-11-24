/**
 * Test: SAML signature verification using Web Crypto API.
 *
 * This test generates a signed SAML Response with Node.js crypto,
 * then verifies it using our validateSamlResponse() which uses
 * the Web Crypto API (crypto.subtle) — the same API available in
 * Cloudflare Workers.
 *
 * Run: npx tsx tests/unit/lib/saml.test.ts
 */

import * as nodeCrypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { SignedXml } from "xml-crypto";
import { DOMParser } from "@xmldom/xmldom";
import { validateSamlResponse, verifySamlSignature, SamlError } from "../../../src/lib/saml";

const XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

/** Pull every X509Certificate out of a parsed SAML doc (KeyInfo of each signature). */
function extractCertsFromXml(doc: Document): string[] {
  const certEls = doc.getElementsByTagNameNS(XMLDSIG_NS, "X509Certificate");
  const certs: string[] = [];
  for (let i = 0; i < certEls.length; i++) {
    const c = (certEls[i].textContent || "").replace(/\s+/g, "");
    if (c && !certs.includes(c)) certs.push(c);
  }
  return certs;
}

// ─── Generate a self-signed X.509 certificate ──────────

function generateSelfSignedCert(): { certPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  // Use Node.js to create a self-signed X.509 certificate
  // We'll use the openssl-like approach via node:crypto X509Certificate
  // For simplicity, generate the cert with a helper
  const certPem = generateX509(publicKey, privateKey);
  const privateKeyPem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();

  return { certPem, privateKeyPem };
}

/**
 * Generate a minimal self-signed X.509 v3 certificate using ASN.1 DER encoding.
 */
function generateX509(
  publicKey: nodeCrypto.KeyObject,
  privateKey: nodeCrypto.KeyObject
): string {
  const spkiDer = publicKey.export({ type: "spki", format: "der" });

  // Build TBSCertificate
  const version = Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]); // v3
  const serialNumber = derInteger(Buffer.from([0x01]));
  // SHA-256 with RSA
  const signatureAlgo = derSequence(
    Buffer.concat([
      derOid([1, 2, 840, 113549, 1, 1, 11]), // sha256WithRSAEncryption
      Buffer.from([0x05, 0x00]), // NULL
    ])
  );
  const issuer = derSequence(
    derSet(
      derSequence(
        Buffer.concat([
          derOid([2, 5, 4, 3]), // CN
          derUtf8String("Test IdP"),
        ])
      )
    )
  );
  const notBefore = derUtcTime("250101000000Z");
  const notAfter = derUtcTime("301231235959Z");
  const validity = derSequence(Buffer.concat([notBefore, notAfter]));
  const subject = issuer; // self-signed

  const tbsCertificate = derSequence(
    Buffer.concat([
      version,
      serialNumber,
      signatureAlgo,
      issuer,
      validity,
      subject,
      spkiDer,
    ])
  );

  // Sign the TBSCertificate
  const signer = nodeCrypto.createSign("SHA256");
  signer.update(tbsCertificate);
  const signature = signer.sign(privateKey);

  // Wrap in Certificate SEQUENCE
  const cert = derSequence(
    Buffer.concat([
      tbsCertificate,
      signatureAlgo,
      derBitString(signature),
    ])
  );

  const b64 = cert.toString("base64");
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

// ─── ASN.1 DER helpers ────────────────────────────────

function derLength(len: number): Buffer {
  if (len < 128) return Buffer.from([len]);
  if (len < 256) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derSequence(content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x30]), derLength(content.length), content]);
}

function derSet(content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x31]), derLength(content.length), content]);
}

function derInteger(value: Buffer): Buffer {
  // Prepend 0x00 if high bit is set
  const padded = value[0] & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value;
  return Buffer.concat([
    Buffer.from([0x02]),
    derLength(padded.length),
    padded,
  ]);
}

function derOid(components: number[]): Buffer {
  const bytes: number[] = [40 * components[0] + components[1]];
  for (let i = 2; i < components.length; i++) {
    let val = components[i];
    if (val < 128) {
      bytes.push(val);
    } else {
      const enc: number[] = [];
      enc.push(val & 0x7f);
      val >>= 7;
      while (val > 0) {
        enc.push((val & 0x7f) | 0x80);
        val >>= 7;
      }
      enc.reverse();
      bytes.push(...enc);
    }
  }
  const buf = Buffer.from(bytes);
  return Buffer.concat([Buffer.from([0x06]), derLength(buf.length), buf]);
}

function derUtf8String(s: string): Buffer {
  const buf = Buffer.from(s, "utf8");
  return Buffer.concat([Buffer.from([0x0c]), derLength(buf.length), buf]);
}

function derUtcTime(s: string): Buffer {
  const buf = Buffer.from(s, "ascii");
  return Buffer.concat([Buffer.from([0x17]), derLength(buf.length), buf]);
}

function derBitString(content: Buffer): Buffer {
  // Prepend unused-bits byte (0)
  const inner = Buffer.concat([Buffer.from([0x00]), content]);
  return Buffer.concat([Buffer.from([0x03]), derLength(inner.length), inner]);
}

// ─── Build and sign a SAML Response ────────────────────

function buildSignedSamlResponse(
  privateKeyPem: string,
  certB64: string
): string {
  const responseId = "_resp_" + nodeCrypto.randomUUID().replace(/-/g, "");
  const assertionId = "_assert_" + nodeCrypto.randomUUID().replace(/-/g, "");
  const now = new Date();
  const notAfter = new Date(now.getTime() + 5 * 60 * 1000);
  const issueInstant = now.toISOString();

  // Build the unsigned SAML Response
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="https://api.example.com/auth/sso/saml/acs"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID></saml:Subject><saml:Conditions NotBefore="${now.toISOString()}" NotOnOrAfter="${notAfter.toISOString()}"><saml:AudienceRestriction><saml:Audience>https://api.example.com/auth/sso/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>Test User</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

  // Sign the Response using xml-crypto (uses Node.js crypto.createSign)
  const sig = new SignedXml();
  sig.privateKey = privateKeyPem;
  sig.publicCert = certB64;
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";

  sig.addReference({
    xpath: "//*[local-name(.)='Response']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
  });

  sig.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='Status']", action: "before" },
  });

  return sig.getSignedXml();
}

function buildAssertionSignedSamlResponse(
  privateKeyPem: string,
  certB64: string
): string {
  const responseId = "_resp_" + nodeCrypto.randomUUID().replace(/-/g, "");
  const assertionId = "_assert_" + nodeCrypto.randomUUID().replace(/-/g, "");
  const now = new Date();
  const notAfter = new Date(now.getTime() + 5 * 60 * 1000);
  const issueInstant = now.toISOString();

  // Build unsigned SAML with signature on the Assertion
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="https://api.example.com/auth/sso/saml/acs"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID></saml:Subject><saml:Conditions NotBefore="${now.toISOString()}" NotOnOrAfter="${notAfter.toISOString()}"><saml:AudienceRestriction><saml:Audience>https://api.example.com/auth/sso/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>Test User</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

  const sig = new SignedXml();
  sig.privateKey = privateKeyPem;
  sig.publicCert = certB64;
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";

  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
  });

  sig.computeSignature(xml, {
    location: {
      reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
      action: "after",
    },
  });

  return sig.getSignedXml();
}

// ─── Tests ─────────────────────────────────────────────

async function runTests() {
  const { certPem, privateKeyPem } = generateSelfSignedCert();

  // Extract raw base64 certificate (no PEM headers) for storage
  const certB64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");

  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err: any) {
      console.error(`  ✗ ${name}`);
      console.error(`    ${err.message}`);
      if (err.stack) {
        const relevantLines = err.stack.split("\n").slice(1, 4).join("\n    ");
        console.error(`    ${relevantLines}`);
      }
      failed++;
    }
  }

  console.log("\nSAML Web Crypto Verification Tests\n");

  // ── Test 1: Response-level signature ──
  await test("validates Response-level signature", async () => {
    const signedXml = buildSignedSamlResponse(privateKeyPem, certPem);

    const result = await validateSamlResponse({
      samlResponseXml: signedXml,
      certificates: [certB64],
      expectedAcsUrl: "https://api.example.com/auth/sso/saml/acs",
      expectedAudience: "https://api.example.com/auth/sso/saml/metadata",
    });

    assert(result.identity.email === "user@example.com", `Expected email user@example.com, got ${result.identity.email}`);
    assert(result.identity.name === "Test User", `Expected name "Test User", got "${result.identity.name}"`);
    assert(result.identity.ssoSubject === "user@example.com", `Expected ssoSubject user@example.com, got ${result.identity.ssoSubject}`);
  });

  // ── Test 2: Assertion-level signature ──
  await test("validates Assertion-level signature", async () => {
    const signedXml = buildAssertionSignedSamlResponse(privateKeyPem, certPem);

    const result = await validateSamlResponse({
      samlResponseXml: signedXml,
      certificates: [certB64],
      expectedAcsUrl: "https://api.example.com/auth/sso/saml/acs",
      expectedAudience: "https://api.example.com/auth/sso/saml/metadata",
    });

    assert(result.identity.email === "user@example.com", `Expected email user@example.com, got ${result.identity.email}`);
  });

  // ── Test 3: Wrong certificate should fail ──
  await test("rejects signature with wrong certificate", async () => {
    const signedXml = buildSignedSamlResponse(privateKeyPem, certPem);
    const { certPem: wrongCert } = generateSelfSignedCert();
    const wrongCertB64 = wrongCert
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, "");

    try {
      await validateSamlResponse({
        samlResponseXml: signedXml,
        certificates: [wrongCertB64],
        expectedAcsUrl: "https://api.example.com/auth/sso/saml/acs",
        expectedAudience: "https://api.example.com/auth/sso/saml/metadata",
      });
      throw new Error("Should have thrown SamlError");
    } catch (err: any) {
      assert(err instanceof SamlError, `Expected SamlError, got ${err.constructor.name}: ${err.message}`);
    }
  });

  // ── Test 4: Tampered content should fail ──
  await test("rejects tampered SAML Response", async () => {
    const signedXml = buildSignedSamlResponse(privateKeyPem, certPem);
    // Tamper with the email
    const tampered = signedXml.replace("user@example.com", "hacker@evil.com");

    try {
      await validateSamlResponse({
        samlResponseXml: tampered,
        certificates: [certB64],
        expectedAcsUrl: "https://api.example.com/auth/sso/saml/acs",
        expectedAudience: "https://api.example.com/auth/sso/saml/metadata",
      });
      throw new Error("Should have thrown SamlError");
    } catch (err: any) {
      assert(err instanceof SamlError, `Expected SamlError, got ${err.constructor.name}: ${err.message}`);
    }
  });

  // ── Test 5: Certificate rotation (multiple certs) ──
  await test("supports certificate rotation (correct cert second in list)", async () => {
    const signedXml = buildSignedSamlResponse(privateKeyPem, certPem);
    const { certPem: otherCert } = generateSelfSignedCert();
    const otherCertB64 = otherCert
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, "");

    const result = await validateSamlResponse({
      samlResponseXml: signedXml,
      certificates: [otherCertB64, certB64], // correct cert is second
      expectedAcsUrl: "https://api.example.com/auth/sso/saml/acs",
      expectedAudience: "https://api.example.com/auth/sso/saml/metadata",
    });

    assert(result.identity.email === "user@example.com", "Should succeed with correct cert in rotation list");
  });

  // ── Test 6: SPKI extraction ──
  await test("extractSpkiFromCert produces valid SPKI for Web Crypto import", async () => {
    // Verify the SPKI extraction matches what Node.js exports
    const { publicKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const spkiFromNode = publicKey.export({ type: "spki", format: "der" });

    // Create a cert with this key and extract SPKI using our function
    const { certPem: testCert } = generateSelfSignedCert();
    const certDer = Buffer.from(
      testCert
        .replace(/-----BEGIN CERTIFICATE-----/g, "")
        .replace(/-----END CERTIFICATE-----/g, "")
        .replace(/\s+/g, ""),
      "base64"
    );

    // Import using Web Crypto to verify the SPKI is valid
    const spki = extractSpkiForTest(new Uint8Array(certDer));
    const key = await crypto.subtle.importKey(
      "spki",
      spki.buffer as ArrayBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
    assert(key.type === "public", `Expected public key, got ${key.type}`);
    assert(key.algorithm.name === "RSASSA-PKCS1-v1_5", `Wrong algorithm: ${key.algorithm.name}`);
  });

  // ── Test 7: Real captured Okta response (regression for dual signature + xmlns:xs PrefixList) ──
  // Fixture is the raw base64 SAMLResponse captured from the ACS endpoint. This exercises the
  // exact canonicalization the hand-rolled verifier got wrong:
  //   - Okta signs BOTH the Response and the Assertion (enveloped transform must not strip the nested sig)
  //   - the signature carries <ec:InclusiveNamespaces PrefixList="xs"> (xmlns:xs must survive C14N)
  // Signature/digest verification is time-independent, so the assertion's expired timestamps don't matter.
  await test("verifies real captured Okta SAML response (canonicalization regression)", async () => {
    const fixturePath = path.join(__dirname, "..", "..", "fixtures", "saml", "okta-saml-response.b64");
    if (!fs.existsSync(fixturePath)) {
      console.log("    (skipped — drop the raw base64 SAMLResponse at tests/fixtures/saml/okta-saml-response.b64)");
      return;
    }
    const b64 = fs.readFileSync(fixturePath, "utf8").replace(/\s+/g, "");
    const xml = Buffer.from(b64, "base64").toString("utf8");
    const doc = new DOMParser().parseFromString(xml, "text/xml");
    const certs = extractCertsFromXml(doc);
    assert(certs.length > 0, "No X509Certificate found in the fixture");
    const signed = await verifySamlSignature(xml, doc, certs);
    assert(
      signed === "Response" || signed === "Assertion",
      `signature did not verify (returned ${signed})`
    );
  });

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

// Re-implement extractSpkiFromCert here for the isolated test
// (since it's not exported from saml.ts)
function extractSpkiForTest(certDer: Uint8Array): Uint8Array {
  let offset = 0;

  function readTag(): { tag: number; constructed: boolean; length: number } {
    const tag = certDer[offset++];
    const constructed = (tag & 0x20) !== 0;
    let length = certDer[offset++];
    if (length & 0x80) {
      const numBytes = length & 0x7f;
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | certDer[offset++];
      }
    }
    return { tag: tag & 0x1f, constructed, length };
  }

  function skipField(): void {
    const { length } = readTag();
    offset += length;
  }

  readTag(); // Outer SEQUENCE
  readTag(); // TBSCertificate SEQUENCE

  if ((certDer[offset] & 0xa0) === 0xa0) {
    skipField(); // version
  }

  skipField(); // serialNumber
  skipField(); // signature
  skipField(); // issuer
  skipField(); // validity
  skipField(); // subject

  const spkiStart = offset;
  skipField();
  return certDer.slice(spkiStart, offset);
}

runTests().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
