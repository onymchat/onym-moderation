# Llama-Guard-4-12B Reference Authority — Terms

**Model profile, version 1 — 8 August 2026**

These terms are shown when you select the **Llama-Guard-4-12B Reference
Authority**. They incorporate the [Onym Reference Moderation
Policy](../REFERENCE-AUTHORITY-POLICY.md), version 1, whose canonical UTF-8
bytes (LF line endings, no byte-order mark) have SHA-256
`8609e064f9615e29fad4fb97e3feed533dd4a01986f9fc73e3a2d3fd60f4c08b`.

> **Automated decision:** the locally hosted Llama Guard model applies its
> MLCommons-based native taxonomy, not the canonical Onym rules. `unsafe` with
> a mapped hazard causes the Authority to sign a ban without prior human
> review. A human applies the narrower Onym rule only on appeal.

## Model and deployment

- Repository: `meta-llama/Llama-Guard-4-12B`
- Revision: `87acb4b94e930c3d679e6e7ee9d57e2feab9ea71`
- License: Llama 4 Community License
- Deployment: Authority-controlled infrastructure; report content is not sent
  to Meta or a hosted inference provider
- Inputs enabled by this profile: multilingual text and up to three images

## Exact adapter and native-policy mismatch

The common case document from policy §4.1 is supplied as the sole user turn
through the checkpoint's chat template. Images appear in evidence order before
the text that describes their authenticated envelope. No custom safety policy
is inserted. The adapter accepts exactly `safe`, or `unsafe` followed by one or
more documented hazard IDs, and uses these mappings:

| Onym class | Required Llama Guard hazard |
|---|---|
| `csam` | `S4` — Child Sexual Exploitation |
| `credible-violence` | `S1` — Violent Crimes |
| `unsolicited-pornography` | `S12` — Sexual Content |

- `unsafe` plus the class's required hazard → ban;
- exactly `safe` → dismiss; and
- missing, unknown, contradictory, extra, or unmapped output → no decision.

Only the hazard mapped to the reported class counts. Other hazards do not
expand the mandate.

The native hazards are not identical to the reference rules. In particular,
`S12` does not establish unsolicited transmission or lack of consent, and `S1`
does not by itself establish a specific credible threat. `S4` may cover a
different boundary than the exact `R-CSAM` elements. You accept that mismatch
at first instance; the human appeal reviewer applies the narrower canonical
rule and reverses when its required elements are not proved.

## Limits you accept

Meta describes Llama Guard 4 as a 12B multimodal safety classifier trained on
text and multiple images. It is still a generative model and can be susceptible
to adversarial or prompt-injection attacks. Its model card says image testing
mostly used prompts with three images, so this profile enforces that maximum.
Native-taxonomy coverage, multilingual performance, common-sense judgments,
and missing context can all produce errors.

The Authority stores the final safety label, every returned hazard, adapter
outcome, and input digest. Model documentation: [Meta model
card](https://huggingface.co/meta-llama/Llama-Guard-4-12B).

By selecting **Agree**, you accept the incorporated policy, the disclosed
native-category mismatch, this pinned model and adapter, automated
first-instance enforcement, and human review only on appeal.
