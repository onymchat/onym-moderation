# Qwen3Guard-8B Reference Authority — Terms

**Model profile, version 1 — 8 August 2026**

These terms are shown when you select the **Qwen3Guard-8B Reference Authority**.
They incorporate the [Onym Reference Moderation
Policy](../REFERENCE-AUTHORITY-POLICY.md), version 1, whose canonical UTF-8
bytes (LF line endings, no byte-order mark) have SHA-256
`8609e064f9615e29fad4fb97e3feed533dd4a01986f9fc73e3a2d3fd60f4c08b`.

> **Automated decision:** the locally hosted Qwen3Guard model applies its own
> fixed taxonomy, not the canonical Onym rules. An `Unsafe` label with a mapped
> category causes the Authority to sign a ban without prior human review. A
> human applies the narrower Onym rule only on appeal.

## Model and deployment

- Repository: `Qwen/Qwen3Guard-Gen-8B`
- Revision: `4505cb1a6f1864f21f8b27f7daf1b9a1aab6edbb`
- License: Apache 2.0
- Deployment: Authority-controlled infrastructure; report content is not sent
  to a hosted inference provider
- Inputs enabled by this profile: text only, at most 32,768 model tokens
- Declared language coverage: 119 languages and dialects
- Variant: `Gen`, not the token-streaming classifier

## Exact adapter and native-policy mismatch

The common case document from policy §4.1 is supplied as the sole user message
through the checkpoint's chat template. No custom system policy is inserted.
The adapter accepts only the documented fields `Safety:` and `Categories:` and
uses these mappings:

| Onym class | Required native category |
|---|---|
| `csam` | `Sexual Content or Sexual Acts` |
| `credible-violence` | `Violent` |
| `unsolicited-pornography` | `Sexual Content or Sexual Acts` |

- `Safety: Unsafe` plus the class's required category → ban;
- `Safety: Safe` and `Categories: None` → dismiss;
- `Safety: Controversial` → no decision; and
- a missing, unknown, contradictory, extra, or unmapped field → no decision.

Only the category mapped to the reported class counts. Other native categories
do not expand the mandate.

Qwen3Guard's `Sexual Content or Sexual Acts` category does not establish that a
person is under 18 or that a transmission was unsolicited. Its `Violent`
category includes depictions and instructions that may not be credible threats.
Consequently this automated adapter is materially broader than `R-CSAM`,
`R-PORN`, and `R-VIOLENCE`. You accept that mismatch at first instance; the
human appeal reviewer must apply the narrower canonical rule and reverse when
its required elements are not proved.

## Limits you accept

The model emits three severity labels rather than calibrated probabilities.
This profile deliberately treats `Controversial` as no decision rather than
silently choosing the benchmark's “strict” or “loose” mapping. It cannot inspect
image, video, or audio evidence. Broad native categories, cultural variation,
translation, adversarial text, quotation, and missing context can cause errors.

The Authority stores the native severity, every returned category, adapter
outcome, and input digest. Model documentation: [Qwen model
card](https://huggingface.co/Qwen/Qwen3Guard-Gen-8B) and [official Qwen3Guard
repository](https://github.com/QwenLM/Qwen3Guard).

By selecting **Agree**, you accept the incorporated policy, the disclosed
native-category mismatch, this pinned model and adapter, automated
first-instance enforcement, and human review only on appeal.
