# Okta Device Posture Provider POC IdP

A throwaway SAML IdP for reverse-engineering Okta's [Device Posture Provider](https://help.okta.com/oie/en-us/content/topics/identity-engine/devices/device-assurance-device-posture-idp.htm)
(Early Access) integration. It captures everything Okta sends to the IdP —
headers, query params, form bodies, and the decoded SAML AuthnRequest XML — and
replies with a signed SAML assertion containing device posture facts
(`IsManaged` / `IsCompliant`) per Okta's data contract.

The main question this tool answers: **does Okta send any device identifier to
the posture IdP, or is device identification entirely the IdP's job?**

## Run it

```bash
go run ./tools/okta-device-posture-poc
ngrok http 9999
```

All requests are logged to stdout and saved under `okta-poc-captures/`.
The signing cert/key are generated on first run in `okta-poc-state/` and reused.
ngrok's own inspector at http://localhost:4040 is a useful second view.

Flags:

- `--managed` / `--compliant` (default `true`) — fact values in the assertion
- `--fail` — respond with the `AuthnFailed` / `DEVICE_NOT_MANAGED` error status
  instead of an assertion
- `--respond=false` — capture only, don't post a response back to Okta
- `--issuer` — override the IdP issuer (defaults to `https://<host>/metadata`)

## Okta setup

The Device Posture Provider feature is **Early Access** — enable it under
**Settings > Features** in your Okta admin console (developer orgs work).

1. **Security > Identity Providers > Add identity provider > SAML 2.0**
   - Name: anything (e.g. `Fleet posture POC`)
   - IdP Usage: **Device posture provider**
   - IdP Issuer URI: `https://<ngrok-domain>/metadata`
   - IdP Single Sign-On URL: `https://<ngrok-domain>/sso`
   - IdP Signature Certificate: upload `okta-poc-state/idp-cert.pem`
   - Request Binding: HTTP POST or HTTP Redirect (the tool handles both)
   - Application context: consider enabling "Send Okta application context" to
     see what extra data Okta includes in the request
   - Destination: `https://<ngrok-domain>/sso`
   - Okta Assertion Consumer Service URL: Trust-specific
2. **Security > Device integrations > Endpoint security tab > Add endpoint
   integration > Device posture provider**, pick the platform (e.g. macOS).
3. **Security > Device assurance policies**: create a policy using the device
   posture provider signals (Managed / Compliant).
4. App sign-in policy: add a rule (highest priority) requiring that device
   assurance policy.
5. Sign in to the app and watch the tool's stdout / `okta-poc-captures/`.

## Notes

- The AuthnRequest reaches this server via the **user's browser** (front-channel
  redirect/POST), not server-to-server from Okta.
- Okta signs its AuthnRequests: redirect binding puts `SigAlg`/`Signature` in
  the query string, POST binding embeds a `ds:Signature` in the XML. This tool
  logs but does not validate them.
- The assertion is signed (enveloped, RSA-SHA256, exclusive c14n), matching
  what Okta's "Response or Assertion" signature verification setting accepts.
