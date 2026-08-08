# Shieldstral-3B Reference Authority — Terms

**Model profile, version 1 — 8 August 2026**

These terms are shown when you select the **Shieldstral-3B Reference
Authority**. They incorporate the [Onym Reference Moderation
Policy](../REFERENCE-AUTHORITY-POLICY.md), version 1, whose canonical UTF-8
bytes (LF line endings, no byte-order mark) have SHA-256
`8609e064f9615e29fad4fb97e3feed533dd4a01986f9fc73e3a2d3fd60f4c08b`.

> **Automated decision:** Mistral's locally hosted Shieldstral model makes the
> first decision. A valid violation score at or above `0.90` causes the
> Authority to sign a ban without prior human review. A human reviews the
> merits only on appeal.

## Model and deployment

- Repository: `mistralai/Shieldstral-1.0-3B`
- Revision: `003ec7e2b0bab5f0e6307edbaf186fa5822b76f5`
- License: Apache 2.0
- Deployment: Authority-controlled infrastructure; no report content is sent
  to Mistral AI's hosted API
- Inputs enabled by this profile: text and at most one image, with a combined
  input no longer than 32,000 model tokens
- Declared languages: English, French, Spanish, German, Italian, Portuguese,
  Dutch, Chinese, Japanese, Korean, Arabic, and Russian

## Exact adapter

The Authority makes one call for the reported class. The fixed system message
is:

> Judge whether the Document meets the requirements based on the Query and the
> Instruction provided. Note that the answer can only be "yes" or "no".

`<Instruct>` contains the class's complete canonical rule from policy §2.1 and
this sentence:

> Apply only this rule. Return yes only when every required element is
> supported by the Document; otherwise return no.

`<Query>` is exactly one of:

- `R-CSAM`: `Does the Document violate R-CSAM?`
- `R-VIOLENCE`: `Does the Document violate R-VIOLENCE?`
- `R-PORN`: `Does the Document violate R-PORN?`

`<Document>` is the common case document from policy §4.1. If it contains an
image, the text prefix, image, and remaining context are supplied in that
order. The model emits one `yes` or `no` token. The adapter takes the first-token
log probabilities for case-insensitive `yes` and `no`, keeps the greatest log
probability for each accepted spelling (`yes`, `yes.`, quoted `yes`, and their
`no` forms), and softmax-normalizes those two values into the violation score.

- score **at or above `0.90`** → ban;
- score **at or below `0.20`** → dismiss; and
- score **between `0.20` and `0.90`** → no decision.

Both thresholds are inclusive. Missing log probabilities, absence of either
token family, extra output, or an unparseable score is invalid and therefore no
decision. Scores are not comparable to probabilities established by a human
study; the thresholds are Authority policy choices.

## Limits you accept

Shieldstral is policy-adaptive rather than proof-aware. It may follow
instructions embedded in evidence, misunderstand legal or conversational
context, or misjudge age, consent, intent, credibility, quotation, satire, or a
language on which it performs unevenly. Its model card says it was trained to
32K tokens even though the underlying model can technically accept more; this
profile enforces the trained range.

The Authority stores the final token, normalized score, adapter outcome, and
input digest. It does not treat model reasoning as evidence. The human appeal
review applies the canonical rule, not merely the score.

Model documentation: [Mistral model
card](https://huggingface.co/mistralai/Shieldstral-1.0-3B) and [Shieldstral
announcement](https://mistral.ai/news/shieldstral/).

By selecting **Agree**, you accept the incorporated policy, this pinned model
and adapter, automated first-instance enforcement, and human review only on
appeal.
