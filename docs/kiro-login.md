# Kiro login methods

Kiro credentials can be added from **Management Center → OAuth → Kiro** or from the CLI. The tile
offers one button per method, and every method ends up as an ordinary Kiro auth file, so pooling,
cooldown and failover treat them identically.

| Method | What it needs | Notes |
|---|---|---|
| **Builder ID** | nothing | AWS Builder ID device code; the default. |
| **Google** / **GitHub** | nothing | Social login through Kiro's desktop auth service. Approving a second social account signs the first one out. |
| **Your organization** | Identity Center **start URL** + **region** | AWS IAM Identity Center device code. See below. |
| **API key** | a `ksk_...` key | Validated immediately; no browser step and nothing to poll. |

## Your organization (AWS IAM Identity Center)

The organization flow registers a client against `oidc.{region}.amazonaws.com`, starts a
device-authorization request with your portal start URL and shows the portal device page
`{startUrl}/#/device?user_code=...`, so the operator lands in the organization's own sign-in page
instead of the Builder ID page, which asks for an email address and cannot finish an Identity Center
login.

- The portal URL is normalized to its `/start` form; query and fragment are dropped. Anything that is
  not an `http(s)` URL is rejected with HTTP 400.
- The region must be the one that hosts your identity directory (for example `eu-west-1`). It is used
  for the device authorization *and* for token refresh, so a wrong region breaks refresh later even if
  the login appears to work.
- **External identity providers**: AWS does not offer the device-code flow when your Identity Center
  delegates to an external IdP (Okta, Entra ID, ...). For those organizations run `kiro-cli login`
  once on a machine with a browser and import the resulting credential instead (see below). The same
  caveat is documented by Kiro's own CLI.
- A profile ARN is what tells Keeper the account apart from a Builder ID; an organization credential
  imported without one is classified as `builder-id`, which is also how `kiro-cli` stores Builder ID.

CLI equivalent:

```bash
cli-proxy-api-plus --kiro-idc-login \
  --kiro-idc-start-url https://example.awsapps.com/start \
  --kiro-idc-region eu-west-1 \
  --kiro-idc-flow device
```

The default `--kiro-idc-flow authcode` opens a `127.0.0.1` callback server, so it only works when the
operator's browser runs on the same host as the proxy. Use `device` on a remote or headless host.

## API key

Kiro issues per-profile API keys that start with `ksk_`. Management Center validates the key against
`https://management.us-east-1.kiro.dev/` (`AmazonCodeWhispererService.GetProfile`) before saving it,
and the runtime sends it as `Authorization: Bearer <key>` plus `tokentype: API_KEY`.

API keys have no refresh token, so they are stored with `auth_method: apikey`, skipped by the
background refresh sweep, and stay valid until Kiro revokes them. A revoked key surfaces as an
upstream 401/403 rather than as a refresh failure.

## Importing from kiro-cli

`--kiro-import` (and the Management Center auth-file import) reads the `kiro-cli` SQLite store, the
`KIRO_CREDS_FILE` / `KIRO_CREDENTIALS_FILE` JSON, or Kiro IDE credentials. The Identity Center keys
`kirocli:odic:token`, `kirocli:oidc:token` and `codewhisperer:odic:token` are all recognized together
with their `device-registration` rows, which is the supported path for organization accounts whose
Identity Center rejects the device-code flow.

```bash
cli-proxy-api-plus --kiro-import
```
