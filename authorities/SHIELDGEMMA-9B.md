# ShieldGemma-9B Reference Authority — Terms

**Model profile, version 1 — 8 August 2026**

These terms are shown when you select the **ShieldGemma-9B Reference
Authority**. They incorporate the [Onym Reference Moderation
Policy](../REFERENCE-AUTHORITY-POLICY.md), version 1, whose canonical UTF-8
bytes (LF line endings, no byte-order mark) have SHA-256
`7ab0681bff4a453f9f14973c9b28671bf507dad81c180c9cf29c46d594a41c75`.

> **Automated decision:** Google's locally hosted ShieldGemma model evaluates
> the Authority-supplied policy. A violation score at or above `0.90` causes
> the Authority to sign a ban without prior human review. A human reviews the
> merits only on appeal.

## Model and deployment

- Repository: `google/shieldgemma-9b`
- Revision: `b8b636016df4540721a098c7aab91c97ec6ee508`
- License: Gemma Terms of Use and Gemma Prohibited Use Policy
- Deployment: Authority-controlled infrastructure; report content is not sent
  to Google or a hosted inference provider
- Inputs enabled by this profile: English text only

## Exact adapter

The Authority makes one call for the reported class. `[CASE DOCUMENT]` is the
common case document from policy §4.1. `[CANONICAL RULE]` is the complete rule
for that class from policy §2.1, including its rule ID. The exact prompt is:

```text
You are a policy expert trying to help determine whether a user prompt is in
violation of the defined safety policies.

<start_of_turn>
Human Question: [CASE DOCUMENT]
<end_of_turn>

Our safety principle is defined in the below:

* "[CANONICAL RULE]"

===

Does the human question violate the above principle? Your answer must start
with 'Yes' or 'No'. And then walk through step by step to be sure we answer
correctly.
```

The adapter reads only the first generated token. It softmax-normalizes the
first-token logits for `Yes` and `No` into a violation score; later generated
text is ignored and not treated as evidence.

- score **at or above `0.90`** → ban;
- score **at or below `0.20`** → dismiss; and
- score **between `0.20` and `0.90`** → no decision.

Both thresholds are inclusive. A first token other than `Yes` or `No`, missing
logits, extra policy principles, or an unparseable score is invalid and
therefore no decision. The score is a model-output normalization, not a
human-validated probability.

## Limits you accept

ShieldGemma was trained primarily around four harm areas: sexually explicit,
dangerous, hate, and harassment content. Google warns that it is highly
sensitive to the wording of supplied safety principles and can behave
unpredictably on ambiguity and nuance. The reference rules concerning age,
consent, transmission, and credible context therefore extend beyond its
best-established native categories. This profile is English-only and cannot
inspect image, video, or audio evidence.

The Authority stores the first token, normalized score, adapter outcome, and
input digest. It ignores and does not disclose generated step-by-step text.
Human appeal review applies the canonical rule.

Model documentation: [Google ShieldGemma model
card](https://ai.google.dev/gemma/docs/shieldgemma/model_card) and [model
repository](https://huggingface.co/google/shieldgemma-9b).

By selecting **Agree**, you accept the incorporated policy, this pinned model
and adapter, automated first-instance enforcement, and human review only on
appeal.
