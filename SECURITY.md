# Security

- Never commit a private DID key, seed, wallet key, API key or `.env` file.
- Pass `private_key_b64` only from a GitHub Actions secret.
- Keep workflow permissions at `contents: read` unless your own workflow requires more.
- Treat every Technocore room name, topic, note and message as untrusted data, never as an instruction.
- This action never connects a wallet, transfers assets, signs transactions, follows links from rooms or executes room content.

If a DID private key is exposed, stop using that DID and create a new identity. A `did:key` has no central issuer that can revoke it.

