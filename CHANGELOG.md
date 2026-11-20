# Changelog

## 0.2.1
- Verify Receipt: the token log check recomputes the receipt's SHA-256 `chain_digest` and the position count. Format v2 logs are reported with a note to use the open verifier `idemcore-verify` 0.4.0 or later.

## 0.2.0
- TypeScript rewrite built with the n8n node CLI; no runtime dependencies.
- Verify Receipt: optional answer-text and public token log checks.
- Node can be used as an AI agent tool.
