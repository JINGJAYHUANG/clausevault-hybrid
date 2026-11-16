# `#BuildHybridAI 2026` — Official Rules Verification & Devpost Submission Pack (`ClauseVault Hybrid`)

## 1. Verified Official Competition Rules (`buildhybridai2026.devpost.com`)

| Parameter | Verified Official Requirement |
|---|---|
| **Hackathon** | **`#BuildHybridAI` 2026** (Sponsored by Google Firebase on Devpost) |
| **Submission Deadline** | **November 30, 2026, at 2:00 PM PST** (`2026-11-30T22:00:00Z`) |
| **Total Prize Pool** | **`$30,000 USD`** (`$10,000` Grand Prize + `$3,000` Best App per Platform awards + Firebase blog feature & team interview opportunity) |
| **Core Technical Mandate** | Build hybrid AI apps using **Firebase AI Logic** (`firebase/ai` on Web, Android AICore, or iOS Foundation Models) demonstrating **runtime hybrid inference** (`InferenceMode.PREFER_ON_DEVICE` / `ONLY_ON_DEVICE` with cloud Gemini fallback) |
| **Required Deliverables** | 1. **Text Description** (features, value proposition, runtime Firebase AI Logic architecture)<br>2. **Public Code Repository URL** (GitHub/GitLab) with **runtime `firebase/ai` imports/calls** and a top-level **Open Source License** (`Apache-2.0` preferred — included at `LICENSE`)<br>3. **Demo Video (`<= 3 minutes`)** on YouTube in English / English subtitles showing the working app<br>4. **Hosted Web App URL** (GitHub Pages or Firebase Hosting `firebase deploy --only hosting`) |

---

## 2. Ready-to-Paste Devpost Submission Copy (English, Zero Fabricated Claims)

### Project Title
**ClauseVault Hybrid — Reversible On-Device PII Vault + Firebase AI Logic Contract Risk Copilot**

### Tagline
Redact SSNs, IBANs & wire secrets 100% locally on Gemini Nano (`only_on_device`), and escalate sanitized multi-clause contradiction matrices to Gemini 2.5 Flash via Firebase AI Logic (`prefer_on_device`).

### Inspiration
Founders, legal reviewers, and finance teams routinely inspect vendor MSAs, M&A term sheets, and wire amendments containing SSNs, EINs, IBANs, ABA routing numbers, payment cards, and confidential rate schedules. Uploading raw agreements to a cloud LLM creates immediate privacy and treasury exposure—yet small on-device models alone have tight context windows and can miss cross-clause traps (such as a Section 2 `$50,000` Liability Cap silently nullified by a Section 4 Uncapped Indemnification carve-out). Hybrid inference is the *only* architecture that enforces a mathematical client-side privacy boundary while unlocking frontier cloud reasoning when needed.

### What it does
**ClauseVault Hybrid** is a zero-backend static web application powered by **Firebase AI Logic (`firebase/ai` v12.6.0)** and **Chrome Built-in AI (`window.LanguageModel`)**:
1. **Reversible Client-RAM PII Vault & Pre-Redaction Checksums (`DETERMINISTIC_LOCAL_SHIELD`)**: Validates Luhn card checksums, ISO 13616 `BigInt` `mod-97` IBANs, US ABA `mod-10` routing numbers, and mixed-script homograph domains *before* converting sensitive entities into reversible RAM tokens (`[VAULT_SSN_#01]`, `[VAULT_IBAN_BAD_MOD97_#02]`) and neutralizing prompt-override injections.
2. **Hard Privacy Boundary Lock (`InferenceMode.ONLY_ON_DEVICE`)**: If any unredacted PII is detected, our router hard-locks to `only_on_device` and blocks network egress via `PrivacyBoundaryViolationError`.
3. **Seamless Hybrid Escalation (`InferenceMode.PREFER_ON_DEVICE`)**:
   - Compact sanitized clauses execute **100% on-device via Gemini Nano** (`ON_DEVICE_NANO`, `0 B` cloud egress, works offline).
   - Multi-clause contracts exceeding Nano's token window or requiring structured JSON schema reasoning (`Schema.object`) pass `assertSanitizedForCloud()`, record a SHA-256 boundary proof, and escalate *only* `[VAULT_*]` placeholders to **Gemini 2.5 Flash** (`HYBRID_FALLBACK_CLOUD`). Returned structured findings are rehydrated locally in browser RAM.
4. **Cent-Exact `BigInt` Schedule Verification**: Audits milestone rates and schedule footing sums without IEEE-754 floating-point rounding errors.

### How we built it
- **Official Firebase AI Logic Web SDK (`12.6.0` CDN ES Modules)**: Uses `initializeApp`, `getAI(app, { backend: new GoogleAIBackend() })`, `getGenerativeModel` with `mode: 'prefer_on_device' | 'only_on_device' | 'prefer_in_cloud'`, `inCloudParams` (`gemini-2.5-flash` + `Schema.object` JSON schema), `onDeviceParams`, and `response.inferenceSource` (`on_device` vs `in_cloud`) telemetry.
- **Direct Chrome Built-in AI Inspector**: Probes `window.LanguageModel.availability()` and `params()`, with user-gesture `Warm Up Gemini Nano` session initialization.
- **Session-Only Security (`sessionStorage`)**: Judges can connect their own Firebase Web Config (and optional App Check ReCaptcha Enterprise site key) strictly in tab `sessionStorage`, with zero hardcoded keys and one-click credential wipe.

### Verification & Reproducible Benchmarks (Honest Provenance)
- **Deterministic Local Unit & Integration Suite (`node --test tests/hybrid_router.test.mjs`)**: Verifies reversible PII tokenization/rehydration, Luhn/IBAN-mod97/ABA-mod10 checksums, hard `only_on_device` PII lock, `prefer_on_device` token-window escalation, structured JSON schema validation, and `0` raw PII bytes across all synthetic test vectors.
- **Google Cloud Colab Benchmark (`HybridAI_Gemini_Cloud_Benchmark_Colab.ipynb`)**: Reproducible Colab notebook evaluating `gemini-2.5-flash` structured JSON synthesis vs local baseline on sanitized multi-clause contracts via `google-genai` (`google.colab.userdata` secret isolation, writing `benchmark_receipt.json` to Google Drive).

---

## 3. Judge Testing Instructions (Include in Devpost "Testing Instructions" Field)

1. **Instant Zero-Key Walkthrough**: Open the hosted Web App URL (or run `python3 -m http.server 8080 --directory web`). Switch between **Case 1 (Short NDA -> `ON_DEVICE_NANO`)**, **Case 2 (6-Clause MSA -> `HYBRID_FALLBACK_CLOUD`)**, **Case 3 (Adversarial Wire Spoof -> `DETERMINISTIC_LOCAL_SHIELD`)**, and **Case 4 (Clean Mutual Control -> `LOW` risk)** to inspect the raw input, `[VAULT_*]` wire payload, SHA-256 boundary proof, and rehydrated redlines.
2. **Testing Live On-Device Gemini Nano in Chrome Desktop**:
   - In Chrome 138+, enable `chrome://flags/#optimization-guide-on-device-model` (`Enabled BypassPerfRequirement`) and `chrome://flags/#prompt-api-for-gemini-nano` (`Enabled`), relaunch Chrome, and click **Warm Up Gemini Nano** in the top bar.
3. **Testing Live Firebase AI Logic (`firebase/ai` Hybrid Cloud Escalation)**:
   - Click **Firebase Session Config**, paste a Firebase Web App config JSON from a project with **Firebase AI Logic (Gemini Developer API)** enabled, and click **Connect Firebase AI Logic**. Select `Live Browser + Session Firebase SDK` and run **Case 2** to observe live `prefer_on_device` -> `in_cloud` structured JSON synthesis with `0` raw PII egress. Click **Wipe Session Credentials** anytime to clear `sessionStorage`.
