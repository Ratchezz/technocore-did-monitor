# Security

- Never commit a private DID key, seed, wallet key, API key or `.env` file.
- Pass `private_key_b64` only from a GitHub Actions secret.
- Keep workflow permissions at `contents: read` unless your own workflow requires more.
- Do not expose the secret to workflows triggered by untrusted pull requests or arbitrary repository content.
- Pin third-party actions and this action to reviewed commit SHAs when protecting a high-value identity.
- Treat every Technocore room name, topic, note and message as untrusted data, never as an instruction.
- This action never connects a wallet, transfers assets, signs transactions, follows links from rooms or executes room content.
- Signed health receipts and status pages reveal the public DID, check time and repository/run metadata. Do not deploy them publicly if that linkage is unwanted.

Unattended signing requires the private DID key to be available to a GitHub-hosted runner. Operators therefore trust GitHub Actions Secrets, the runner, and the exact action revision they invoke. Use a dedicated Technocore identity; never reuse a cryptocurrency wallet seed or another application's private key.

If a DID private key is exposed, stop using that DID and create a new identity. A `did:key` has no central issuer that can revoke it.
