# Default Onym Moderation Authority — Terms

**Reference terms, version 1 — 8 August 2026**

These are the terms shown when you select the **Default Onym Moderation
Authority**. The Authority is separate from the Onym interface: the Authority
can decide moderation cases and sign verdicts, but it cannot read your device,
scan your conversations, or write device restrictions itself.

By agreeing, you authorize this Authority to decide only the violation classes
and follow only the procedure stated below. Your signed mandate records the
exact hash of these terms. A later version does not change your mandate without
fresh review and consent.

> **Important:** the first decision is automated. A locally hosted Mistral
> Moderation model scores the text a reporter voluntarily submits. A mapped
> score of `0.90` or higher causes the Authority to issue a ban without prior
> human review. A human reviews the merits only if the user appeals.

## 1. What you are agreeing to

You authorize the Default Onym Moderation Authority to:

1. receive reports from users who selected the same Authority;
2. verify that reported material was voluntarily disclosed by a recipient and
   carries evidence that binds it to the accused identity;
3. open a case only within a violation class listed in §2;
4. use Mistral Moderation to make the initial decision from the disclosed text;
5. give the accused notice and the stated response window before an automated
   ban takes effect;
6. automatically sign a dismissal or ban verdict when the score rules in §4
   decide the case; and
7. provide human review if the accused or a device's new holder appeals.

This authority applies only to the Onym interface and device covered by your
mandate. It is not a protocol-wide ban and does not prevent use of compatible
software that is outside that interface.

Selecting “default” is a convenience, not a claim that this Authority is
neutral, infallible, or mandatory at the protocol layer. Where the interface
offers another authority, you may choose it before signing.

## 2. Violation classes and maximum sanctions

The Authority may open and decide a case only under one of these classes:

| Class | What it covers | Response window | Decision deadline | Maximum ban | Appeal |
|---|---|---:|---:|---:|---|
| Child sexual abuse material (`csam`) | A sexual image or depiction involving a person under 18, or solicitation, distribution, or facilitation of that material. Good-faith safety reports, victim-support communications, and lawful evidence handling are not violations. | 3 days | 7 days | Permanent | 30 days; non-suspensive; an independent appellate authority remains available while a permanent ban is in force |
| Credible violence (`credible-violence`) | A specific threat, incitement, or operational instruction for physical violence where the words and available context make harm reasonably credible. News, documentary, fictional, defensive, or good-faith safety discussion is not a violation merely because it describes violence. | 7 days | 14 days | 365 days | 30 days; non-suspensive |
| Unsolicited pornography (`unsolicited-pornography`) | Intentionally sending explicit sexual material to a person who did not consent to receive it. Consensual exchanges and non-explicit educational, medical, or safety material are not violations. | 7 days | 14 days | 90 days | 30 days; suspensive |

The initial automated decision uses these mappings:

| Onym class | Mistral categories whose scores count |
|---|---|
| `csam` | `sexual`, `sexual/minors` |
| `credible-violence` | `violence_and_threats`, `dangerous_and_criminal_content` |
| `unsolicited-pornography` | `sexual` |

The highest mapped score across all disclosed items is the case score. These
mappings are broader than the definitions above. For example, Mistral's
`sexual` category does not by itself establish that a person is under 18 or
that explicit material was unsolicited. Nevertheless, under these terms a
mapped score at or above the ban threshold controls the first decision. The
definition, context, intent, consent, and any mismatch in the mapping are
considered by a human only on appeal.

A permanent sanction is valid only with a separate appellate authority named
in the manifest. If no living forum can hear an appeal or new-holder claim, the
interface must clear the mark.

## 3. Reports and evidence

A report must be signed by a user whose own mandate names this Authority. It
must identify the accused, the claimed class, and the specific material the
reporter chooses to disclose.

Reported material is evidence of authorship only when its sender signature or
envelope commitment verifies against the accused identity. Material without
that proof may be treated as a complaint or lead, but cannot by itself support
a ban verdict. The Authority does not ask for a whole mailbox, encryption key,
contact list, or material unrelated to the report.

Reports are free. Reporters receive no bounty and the Authority is not paid
more for opening a case or issuing a ban. A reporter's history of upheld and
dismissed reports may affect review priority, but never substitutes for proof.

## 4. Automated decision by Mistral Moderation

### 4.1 Model and score rules

The Authority runs Mistral's `mistral-moderation-2603` model on infrastructure
controlled by the Authority. The model evaluates the voluntarily disclosed
text in the reports joined to a case and returns category scores between zero
and one. The Authority stores the complete assessment, including the model,
every returned category and score, the mapped categories, the deciding score,
and the time of assessment.

The first decision is mechanical:

- score **at or above `0.90`** → automated ban recommendation;
- score **at or below `0.20`** → automated dismissal; and
- score **between `0.20` and `0.90`** → no model decision. The case remains
  open and is dismissed automatically if the decision deadline arrives.

Both thresholds are inclusive. The score is the highest score from the mapped
categories in §2 across all disclosed report items. If the class has no mapped
category, the model cannot ban under that class.

The Mistral result determines the first-instance disposition. The Authority's
software converts it into a signed Onym verdict and sends that verdict to the
interface. Mistral itself does not hold the Authority signing key and cannot
write a device mark, but in ordinary terms **Mistral decides the initial ban**.

### 4.2 No human review before the initial verdict

No moderator checks the report, model mapping, score, context, response, or
class fit before the automated first decision. The non-model checks before a
case opens are mechanical: signatures, mandates, class membership, and
authenticity proof.

The accused may submit a response during the response window. It becomes part
of the case record available on appeal, but it is not reviewed by a human
before the initial automated verdict. A pending ban cannot execute before the
response window closes. The model may dismiss immediately because dismissal is
not a sanction.

The first human merits review occurs only after an ordinary appeal or
new-holder claim. The reviewer sees the disclosed evidence, response,
assessment, category mapping, scores, and original automated verdict.

### 4.3 Known limits and failure behavior

Automated moderation can produce false positives and false negatives,
especially with quotation, reclaimed language, slang, satire, multilingual
content, missing context, age, consent, or intent. The overlap in §2 can also
make a broad Mistral category a poor match for the narrower Onym class. Agreeing
to these terms means accepting that risk at the first decision, subject to the
human appeal right.

An invalid response from the model is an error, not a zero score. If the model
is unavailable or returns no recognizable scores, the case remains open and is
retried. If no valid automated decision lands by the decision deadline, the
case is dismissed. Model failure never becomes a ban and does not route the
case to pre-verdict human review.

Mistral states that moderation models and category scores can change. This
Authority pins the named model and thresholds for these terms. Changing the
model, thresholds, category mapping, or role of automation requires new terms
and applies only to mandates signed after fresh review and consent.

Mistral's category documentation is available at [Moderation &
Guardrailing](https://docs.mistral.ai/en/studio-api/conversations/moderation).
The documentation describes the model taxonomy; it does not expand the
Authority's signed mandate.

## 5. Where classification runs

The Mistral model runs on the Authority's own host. Eligible report text is
sent from the Authority case service to that local model endpoint; it is not
sent to Mistral AI's hosted API under these terms. Mistral AI supplies the model
technology but is not a recipient or case reviewer in this deployment.

Only text a reporter deliberately includes in a report is classified. Images,
video, audio, cryptographic proofs, identity keys, device bindings, signatures,
and device data are not model inputs. Suspected child sexual abuse media is
handled through the Authority's lawful reporting process; the local text model
does not inspect the media itself.

Moving classification to a third-party API would be a new disclosure and a
material change to these terms. The Authority may not do that for an existing
mandate without fresh consent.

## 6. Case procedure

1. **Jurisdiction and authenticity.** The Authority verifies both parties'
   mandates, the claimed class, the report signature, and the evidence's
   authorship proof before treating the material as evidence.
2. **Case opening.** A conforming report opens a case mechanically. A receipt
   for a report alone is not notice that a case opened.
3. **Automated assessment.** The locally hosted Mistral model scores the
   reporter-disclosed text under the category mapping and thresholds in §§2
   and 4. No human pre-screens the case.
4. **Notice.** When the case opens, the interface shows the accused the class,
   intake basis, evidence available under the confidentiality rules, response
   deadline, and decision deadline. The procedural `case-open` mark does not
   reduce service.
5. **Response.** The accused may submit a signed statement and counter-evidence
   throughout the response window. No human reviews it unless an appeal is
   filed. Not responding is not a confession.
6. **Automated decision.** A score at or above `0.90` produces a signed ban
   verdict after the response window; a score at or below `0.20` produces a
   signed dismissal. The verdict reasoning identifies the stored assessment
   whose model output caused the decision.
7. **Default.** If the Authority does not decide by the deadline, the case is
   dismissed and the `case-open` mark clears.

## 7. Appeals and a device's new holder

An accused user may appeal within the period in §2. Appeal is the first time a
human reviews the merits. The reviewer must consider the exact Onym class—not
merely the mapped Mistral category—together with authorship proof, full
disclosed context, the user's response and counter-evidence, the complete model
assessment, and any claimed model or mapping error. The reviewer gives written
reasoning and either upholds the automated ban or issues a new signed reversal
verdict. The original verdict is not edited.

A person who acquired a marked device from somebody else may make a
challenge-bound new-holder claim without possessing the former holder's
identity key. The interface must provide this route for as long as a device ban
is in force. A human reviews these claims on an expedited basis because a
device is not a person.

For a suspensive class, a timely appeal pauses execution until the declared
appeal path resolves. For a non-suspensive class, the ban may remain in force
during appeal, but a successful appeal clears it.

## 8. Confidentiality and retention

The reporter's identity is visible to the Authority but is not disclosed to
the accused without the reporter's consent, except where law requires it. The
accused receives enough evidence and reasoning to answer the case fairly.

The Authority retains disclosed evidence, Mistral triage results, responses,
and decisions only as long as intake, the case, and its appeal require. A
report declined without a case is deleted within 30 days. A completed case
record is deleted within 30 days after its appeal path closes, except for:

- the signed mandate and verdict needed to validate or clear a live mark;
- minimal non-content audit and transparency records; and
- material that law specifically requires the Authority to preserve or report.

Lawful preservation overrides these deletion periods only for the material and
duration the law requires. Case material is not sold, used for advertising, or
used to train Onym or Mistral models.

## 9. Limits of authority

The Authority may not:

- scan devices or conversations;
- obtain encryption keys or undisclosed plaintext;
- act against a user or class absent from the signed mandate;
- use model categories or thresholds other than those disclosed in §§2 and 4;
- substitute undisclosed human judgment or another model for the automated
  first decision;
- write device marks directly;
- impose a longer ban than §2 permits;
- maintain a protocol-wide blacklist; or
- change these terms for an existing mandate.

Nothing here limits lawful emergency reporting, a reporter's right to contact
public authorities, or any person's legal rights. The mandate is not consent to
unlawful content processing and is not a waiver of due process or appeal.

## 10. Changes, availability, and contact

The app displays the Authority's component identity, operator key, manifest
hash, validity period, and working case/appeal contact beside these terms. Use
that in-app route for a case response, appeal, new-holder claim, privacy
request, or complaint about the Authority.

Material changes apply only to future mandates. Existing cases continue under
the version and hash the user accepted. If the Authority becomes unavailable,
open cases dismiss at their deadlines; an existing ban remains only while a
living declared forum can hear an appeal.

By selecting **Agree**, you confirm that you reviewed these terms, including
the automated Mistral decision, the `0.90` ban threshold, the absence of human
review before the first verdict, and the need to appeal to obtain human review.
You consent to that Authority and the classes above for this identity and
device.
