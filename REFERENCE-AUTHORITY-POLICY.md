# Onym Reference Moderation Policy

**Reference policy, version 1 — 8 August 2026**

This is an example policy for an Onym moderation Authority. It is not a
protocol-wide rule. An Authority may publish different classes, definitions,
sanctions, model instructions, thresholds, or appeal terms. Users choose an
Authority and consent to the exact content-addressed terms it publishes.

An Authority claiming this reference policy must incorporate these exact bytes
and one model profile from [`authorities/`](authorities/) into the terms shown
before consent. Its manifest must identify both artifacts by digest. A later
policy, model, prompt, threshold, or adapter does not change an existing
mandate or live case without fresh review and consent.

> **Important:** under every reference model profile, a moderation model makes
> the first decision and the Authority signs the resulting verdict without
> prior human merits review. A human reviews the merits only on appeal.

## 1. Scope of the mandate

By agreeing to an Authority that incorporates this policy, you authorize it to:

1. receive reports from users whose mandates name the same Authority;
2. verify the report, the parties' mandates, the claimed class, and evidence
   binding the disclosed material to the accused identity;
3. decide only a class in §2, using only the model profile incorporated into
   the same terms;
4. notify the accused and accept a response before a ban takes effect;
5. sign a model-determined dismissal or ban within the limits below; and
6. provide human review on an ordinary appeal or new-holder claim.

The Authority cannot read a device, scan conversations, obtain encryption
keys, or write a device restriction. Its signed verdict is an input to the
Onym interface. The mandate applies only to the identity, device, interface,
classes, and validity period it names.

## 2. Violation classes and maximum sanctions

| Class | Definition | Response window | Decision deadline | Maximum ban | Appeal |
|---|---|---:|---:|---:|---|
| Child sexual abuse material (`csam`) | A sexual image or depiction involving a person under 18, or solicitation, distribution, or facilitation of that material. | 3 days | 7 days | Permanent | 30 days; non-suspensive; an independent appellate authority remains available while a permanent ban is in force |
| Credible violence (`credible-violence`) | A specific threat, incitement, or operational instruction for physical violence where the words and available context make harm reasonably credible. | 7 days | 14 days | 365 days | 30 days; non-suspensive |
| Unsolicited pornography (`unsolicited-pornography`) | Intentionally sending explicit sexual material to a person who did not consent to receive it. | 7 days | 14 days | 90 days | 30 days; suspensive |

### 2.1 Canonical policy rules

These rules are the Authority-supplied policy for profiles that support custom
policies. They remain the human appeal standard for every profile, including a
profile that uses broader native model categories.

#### `R-CSAM`

- **Violation:** the authenticated material depicts, describes, solicits,
  distributes, or facilitates sexual material involving a person under 18.
- **Not a violation merely because of its subject:** a good-faith safety
  report, victim-support communication, lawful evidence handling, news report,
  documentary, or medical discussion.
- **Required context:** the model must have evidence supporting both the sexual
  nature of the material and that the person is under 18. If either is absent,
  ambiguous, or rests only on an unsupported assertion, the model must return
  no violation.

#### `R-VIOLENCE`

- **Violation:** a specific threat, incitement, or operational instruction for
  physical violence where the authenticated words and available context make
  the risk of harm reasonably credible.
- **Not a violation merely because of its subject:** news, documentary,
  fictional, defensive, historical, or good-faith safety discussion.
- **Required context:** violent language without a target, act, instruction,
  or credible context is not enough. Quotation and satire are not threats
  merely because their words would be threatening if asserted directly.

#### `R-PORN`

- **Violation:** the authenticated material shows an intentional transmission
  of explicit sexual material to a recipient who had not consented to receive
  it.
- **Not a violation merely because of its subject:** a consensual exchange or
  non-explicit educational, medical, documentary, or safety material.
- **Required context:** explicitness alone is not enough. The evidence must
  support transmission, intent, and absence of recipient consent.

### 2.2 Authority freedom and disclosure

Another Authority may adopt different policy rules. Before consent, it must
publish:

- every class definition, exception, response period, deadline, sanction, and
  appeal rule;
- the exact model repository, revision and artifact digest;
- the complete model prompt or native-category mapping;
- input construction, included context, supported languages and media;
- score or label calculation, aggregation, thresholds, and invalid-output
  behavior;
- whether classification is local or which third party receives case data;
  and
- whether and when a human reviews a decision.

Those values are consented policy, not mutable server configuration. An
Authority may publish a new version for future mandates; it may not silently
replace the version governing an existing mandate or case.

## 3. Reports and evidence

A report must be signed by a user whose mandate names the Authority. It must
identify the accused, claimed class, and specific material the reporter chooses
to disclose.

Material is evidence of authorship only when its sender signature or envelope
commitment verifies against the accused identity. Unauthenticated material may
be retained as a complaint or lead, but cannot by itself support a ban. The
Authority does not request a whole mailbox, encryption key, contact list, or
material unrelated to the report.

Reports are free. Reporters receive no bounty, and the Authority is not paid
more for opening a case or issuing a ban. Report history may affect intake
priority but never substitutes for evidence.

## 4. Model decision

### 4.1 Common case document

The model profile defines the concrete prompt syntax. Logically, the classified
document contains these labeled fields in this order:

1. `CLASS`: exactly one class identifier from §2;
2. `REPORTED MATERIAL`: only authenticated material disclosed for the report;
3. `REPORT CONTEXT`: the reporter's signed explanation and mechanically
   verified metadata relevant to the class; and
4. `ACCUSED RESPONSE`: the accused's signed response and counter-evidence, or
   the literal value `NONE`.

Untrusted text remains inside its field and never becomes a system instruction,
policy, or model configuration. The Authority assesses the completed case
document after the response window. It may dismiss earlier for a mechanical
jurisdiction or evidence failure, but it may not issue a ban early.

### 4.2 Model-profile outcome

The incorporated model profile is authoritative for converting a valid model
output into one of three outcomes:

- **ban:** sign the class's maximum sanction after the response window;
- **dismiss:** sign a dismissal and clear the procedural mark; or
- **no decision:** keep the case open until a valid retry or the deadline.

The Authority does not convert a missing, malformed, truncated, out-of-policy,
or unmapped output into a ban. It does not substitute a different model,
threshold, category, prompt, or human judgment. If no valid model decision
lands by the deadline, the case is dismissed.

The signed verdict identifies the policy digest, model profile digest, model
revision, class, input-evidence digest, raw final model output, adapter outcome,
and assessment time. Private chain-of-thought is neither a verdict reason nor
evidence and need not be retained or disclosed.

### 4.3 No human review before the first verdict

No moderator checks class fit, model output, context, or the accused's response
before the first-instance verdict. Pre-verdict checks are mechanical:
signatures, mandates, class membership, deadlines, and authenticity proofs.

The first human merits review occurs only after an ordinary appeal or
new-holder claim. Automated moderation can make false positive and false
negative decisions, especially with quotation, slang, satire, multilingual
content, missing context, age, consent, intent, and adversarial input. Agreeing
means accepting that first-instance risk under the selected model profile,
subject to the appeal right.

## 5. Case procedure

1. **Intake.** Mechanical checks validate the report, mandates, class, and
   authorship proof.
2. **Opening and notice.** A conforming report opens a case. The accused sees
   the class, intake basis, available evidence, response deadline, decision
   deadline, policy digest, and model profile.
3. **Response.** The accused may submit a signed statement and counter-evidence
   throughout the response window. Silence is not a confession.
4. **Automated assessment.** After the response window, the pinned model and
   adapter evaluate the case document. No human pre-screens it.
5. **Verdict.** A valid model outcome causes the Authority to sign the
   corresponding ban or dismissal. The interface applies a ban only after the
   response window.
6. **Default.** If the Authority has no valid decision by the deadline, the
   case dismisses and the procedural mark clears.

## 6. Appeals and a device's new holder

An accused user may appeal within the period in §2. This is the first human
merits review. The reviewer applies the exact canonical rule in §2.1, not a
broader native model category, and considers authorship proof, disclosed
context, the response, model input and final output, adapter behavior, and any
claimed policy or model error. The reviewer provides written reasons and signs
an affirming or reversing verdict; the original verdict is never edited.

A person who acquired a marked device from somebody else may make a
challenge-bound new-holder claim without the former holder's identity key. A
human reviews it on an expedited basis. A device is not a person.

A timely appeal pauses a suspensive sanction. A non-suspensive sanction may
remain in force during appeal. A permanent sanction is valid only while the
manifest's independent appellate authority can hear an appeal or new-holder
claim; otherwise the interface must clear it.

## 7. Confidentiality and retention

The Authority knows the reporter's identity but does not disclose it to the
accused without consent unless law requires. The accused receives enough
evidence and reasoning to answer fairly.

The Authority retains disclosed evidence, responses, final model outputs, and
decisions only as long as intake, the case, and appeal require. A declined
report is deleted within 30 days. A completed case record is deleted within 30
days after its appeal path closes, except for:

- the signed mandate and verdict needed to validate or clear a live mark;
- minimal non-content audit and transparency records; and
- material law specifically requires it to preserve or report.

Case material is not sold, used for advertising, or used to train a model.
Changing local classification to a third-party API is a material disclosure
change and requires fresh consent for future mandates.

## 8. Limits and availability

The Authority may not scan devices or conversations, obtain keys or undisclosed
plaintext, decide an unconsented class, exceed a maximum sanction, maintain a
protocol-wide blacklist, write device marks directly, or change the governing
terms for an existing mandate.

The app displays the Authority identity, operator key, manifest hash, validity
period, model profile, and working case and appeal routes. If the Authority
becomes unavailable, open cases dismiss at their deadlines; an existing ban
remains only while a living declared forum can hear an appeal.

Nothing here limits lawful emergency reporting, a reporter's right to contact
public authorities, or any person's legal rights. The mandate is not consent
to unlawful processing and is not a waiver of appeal.
