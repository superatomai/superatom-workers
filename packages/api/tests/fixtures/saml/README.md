# SAML signature-verification test fixtures

These fixtures back the regression test in [`../../unit/lib/saml.test.ts`](../../unit/lib/saml.test.ts).

## Why this exists

`saml.ts` contains a **hand-rolled** XML-DSIG verifier built on the Web Crypto API
(`crypto.subtle`) because Cloudflare Workers can't run `xml-crypto`'s Node-based
`SignedXml.checkSignature()`. Hand-rolled XML canonicalization (C14N) is fragile, and
two real, spec-compliant Okta behaviors broke production signature verification:

1. **InclusiveNamespaces PrefixList ignored.** Okta's signature carries
   `<ec:InclusiveNamespaces PrefixList="xs">`. The verifier didn't pass it to the
   canonicalizer, so `xmlns:xs` was dropped from the canonical XML → digest mismatch.
2. **Enveloped-signature transform stripped nested signatures.** Okta signs **both**
   the Response and the Assertion. When verifying the Response, the verifier removed
   *all* `<Signature>` elements — including the Assertion's, which is part of the
   content the Response digest covers → digest mismatch.

Both surfaced as the same user-facing error: `SAML signature verification failed`.

## The fixture

- **`okta-saml-response.b64`** — the raw base64 `SAMLResponse` captured from a real
  Okta login at the ACS endpoint (`POST /auth/sso/saml/acs`). It exercises **both** bugs
  above: 2 signatures (Response + Assertion), `PrefixList="xs"`, and `xsi:type`
  attributes that pull `xmlns:xs` into scope.

> **Heads-up — contains real data.** This is a genuine signed assertion, so it embeds a
> real user email and the IdP's signing certificate. It cannot be redacted without
> breaking the signature. Treat it as internal-only.

## Run the test

```bash
cd packages/api
npx tsx tests/unit/lib/saml.test.ts
```

Look for: `✓ verifies real captured Okta SAML response (canonicalization regression)`.

The test decodes the fixture, extracts the certificate from the response's own
`KeyInfo`, and calls `verifySamlSignature()`. It checks **signature + canonicalization
only** — which is time-independent — so the assertion's (now expired) `NotOnOrAfter`
timestamps don't matter. If the fixture file is missing, the test skips gracefully.

## Capture / update the fixture

The most reliable way to get the exact bytes (no deploy needed):

1. Install the **SAML-tracer** browser extension (Chrome/Firefox).
2. Perform an SSO login (a successful one is fine — the structure is identical).
3. In SAML-tracer, open the request to `…/auth/sso/saml/acs`, find the `SAMLResponse`
   POST parameter, and copy its **raw base64** value.
4. Save it as a single line to `okta-saml-response.b64` (no quotes/prefix; whitespace
   is stripped by the test).
5. Re-run the test — a green check means the bytes are correct (a bad capture fails to
   parse/verify rather than silently passing).

**Gotcha:** if you copy from Chrome DevTools → Network → Payload instead, grab the
*decoded* form value. URL-encoded base64 (`%2B`/`%2F`/`%3D` instead of `+`/`/`/`=`)
won't decode. SAML-tracer gives the raw value, which is why it's preferred.
