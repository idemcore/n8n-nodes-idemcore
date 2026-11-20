# @idemcore/n8n-nodes-idemcore

This is an n8n community node. It lets you use [Idemcore](https://idemcore.net) in your n8n workflows.

Idemcore gives every AI answer a signed receipt, so anyone can later check which model and settings produced that exact answer and that nothing was changed afterwards. Checking a receipt is free and works offline.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/sustainable-use-license/) workflow automation platform.

[Installation](#installation) · [Operations](#operations) · [Credentials](#credentials) · [Usage](#usage) · [Pricing](#pricing) · [Resources](#resources)

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation. The package name is `@idemcore/n8n-nodes-idemcore`.

## Operations

- **Chat**: send a prompt (or a JSON array of `{role, content}` messages) and get back the answer text, the `receipt_id`, the signed `receipt`, token usage and, for hash-only receipts, the disclosure `salt`. Needs an Idemcore API key.
- **Verify Receipt**: check a signed receipt locally. Returns `ok`, a `VERIFIED` / `FAILED` verdict, and the result of each check. Optional extra checks: the public token log, and the displayed answer text (with the salt). No API key, no network call, always free.

## Credentials

Create an API key at [idemcore.net](https://idemcore.net), then in n8n add an **Idemcore API** credential and paste the key. Leave **Base URL** at `https://api.idemcore.net` unless you run a self-hosted Idemcore gateway. The Verify Receipt operation does not use the credential.

## Compatibility

Tested with n8n 1.x on Node.js 20 and newer. The package has no runtime dependencies.

## Usage

Example workflow: produce an answer with a receipt, then check it.

1. Add an **Idemcore** node, choose **Chat**, select your credential and enter a prompt.
2. Add a second **Idemcore** node, choose **Verify Receipt**, and set **Receipt** to `{{ $json.receipt }}`.
3. Run the workflow. The second node outputs `"ok": true` and `"verdict": "VERIFIED"`. If anything in the receipt was edited, it outputs `FAILED` with the reason.

You can also verify receipts that come from somewhere else (an email, a webhook, a database row): paste or map the receipt JSON into **Receipt**.

## Pricing

Verifying receipts is always free. Chat is billed per token on your Idemcore account; see [idemcore.net](https://idemcore.net) for current prices.

## Resources

- [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
- [Idemcore n8n guide](https://idemcore.net/integrations/n8n)
- [Idemcore documentation](https://idemcore.net/docs)
- Support: dev@idemcore.net

## Version history

- **0.2.1**: The token log check recomputes the SHA-256 `chain_digest`; format v2 logs point to the open verifier `idemcore-verify` 0.4.0 or later.
- **0.2.0**: TypeScript rewrite built with the n8n node CLI. No runtime dependencies. Adds optional answer-text and token-log checks to Verify Receipt, and usable-as-tool support.
- **0.1.x**: first release.
