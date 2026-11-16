# ClauseVault Hybrid (`firebase-hybrid-ai-v2`)

**Zero-PII On-Device Contract & Remittance Vault (`only_on_device`) + Firebase AI Logic Sanitized Cross-Clause Synthesis (`prefer_on_device` -> Gemini 2.5 Flash)**

Built for **Google `#BuildHybridAI` 2026** (`buildhybridai2026.devpost.com`, deadline `November 30, 2026, 2:00 PM PST`).

- **Live Web App (GitHub Pages)**: [https://jingjayhuang.github.io/clausevault-hybrid/](https://jingjayhuang.github.io/clausevault-hybrid/)
- **Source Repository**: [https://github.com/JINGJAYHUANG/clausevault-hybrid](https://github.com/JINGJAYHUANG/clausevault-hybrid)
- **License**: **Apache-2.0** ([`LICENSE`](./LICENSE))

## Why Hybrid AI Matters Here

Legal teams, founders, and finance controllers routinely review contracts, vendor MSAs, and wire amendments packed with sensitive identifiers (SSNs, EINs, ISO 13616 IBANs, ABA routing numbers, payment cards, signatory names, and confidential pricing).
- **Cloud-only AI** leaks raw PII and unredacted bank coordinates across the network.
- **Local-only small models** struggle when multi-clause contracts exceed Gemini Nano's local token budget or require complex cross-clause structured JSON contradiction matrices (e.g., Section 2 Liability Cap silently overridden by Section 4 Uncapped Indemnification).

**ClauseVault Hybrid** combines both worlds cleanly with **Firebase AI Logic (`firebase/ai` v12.6.0)**:
1. **Reversible Client-RAM PII Vault + Pre-Redaction Checksum Shield (`DETERMINISTIC_LOCAL_SHIELD`)**: Validates Luhn card numbers, ISO 13616 `BigInt` `mod-97` IBANs, US ABA `mod-10` routing numbers, and mixed-script homograph domains *before* tokenizing sensitive entities into reversible RAM placeholders (`[VAULT_SSN_#01]`, `[VAULT_IBAN_BAD_MOD97_#02]`) and stripping untrusted prompt injections.
2. **Hard Privacy Lock (`only_on_device`)**: If unredacted PII is ever present, the router hard-locks execution to `only_on_device` and throws `PrivacyBoundaryViolationError` prior to any cloud call.
3. **Intelligent Hybrid Routing (`prefer_on_device` -> `ON_DEVICE_NANO` or `HYBRID_FALLBACK_CLOUD`)**:
   - Compact sanitized clauses run **100% locally on Chrome Built-in AI Gemini Nano** (`0` network bytes, `$0` API cost, offline capable).
   - Multi-clause contracts exceeding Nano's context window or requiring structured JSON schema synthesis pass `vault.assertSanitizedForCloud()`, record a cryptographic SHA-256 privacy boundary proof, and escalate *only* sanitized `[VAULT_*]` tokens to **Gemini 2.5 Flash** via Firebase AI Logic (`GoogleAIBackend` + `Schema.object`), rehydrating tokens locally in browser memory upon return.

## Quick Start (Zero Build Step, Zero `npm install` Required)

### 1. Run Deterministic Unit & Integration Tests (`node --test`)
```bash
node --test tests/hybrid_router.test.mjs
```

### 2. Run Static Web App Locally (Ready for GitHub Pages / Firebase Hosting)
```bash
python3 -m http.server 8080 --directory web
```
Open `http://localhost:8080`:
- **Instant Deterministic Preview**: Works out of the box with zero keys.
- **Chrome Built-in AI (Gemini Nano)**: On Chrome 138+, enable `#optimization-guide-on-device-model` and `#prompt-api-for-gemini-nano`, then click **Warm Up Gemini Nano**.
- **Live Firebase AI Logic**: Click **Firebase Session Config** and paste your Firebase Web Config (`{ apiKey, projectId, appId }`). Credentials stay strictly in tab `sessionStorage` and can be wiped with one click.

### 3. Run Real Google Cloud Gemini Benchmark on Colab
Open `HybridAI_Gemini_Cloud_Benchmark_Colab.ipynb` in Google Colab, store `GEMINI_API_KEY` in Colab Secrets (`google.colab.userdata`), and run all cells to generate a verified `benchmark_receipt.json` on Google Drive (`runtime.unassign()` runs automatically in `finally:`).

## License
Licensed under the **Apache License, Version 2.0** ([LICENSE](./LICENSE)).
