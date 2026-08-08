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

> **Important:** Mistral Moderation performs first-pass triage of eligible text
> that a reporter voluntarily submits. This means disclosed report text is sent
> to Mistral AI. Mistral does not decide cases or bans. A classifier score is
> neither proof nor a verdict.

## 1. What you are agreeing to

You authorize the Default Onym Moderation Authority to:

1. receive reports from users who selected the same Authority;
2. verify that reported material was voluntarily disclosed by a recipient and
   carries evidence that binds it to the accused identity;
3. use Mistral Moderation to prioritize and route eligible disclosed text;
4. open a case only within a violation class listed in §2;
5. give the accused notice and the stated response window;
6. make a reasoned human decision before the decision deadline; and
7. sign a verdict that the Onym interface validates and enforces mechanically.

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

The definition in this document controls. A Mistral category with a similar
name is only a triage signal and cannot broaden a class. In particular,
Mistral's broader `sexual`, `violence_and_threats`, `dangerous`, or `criminal`
categories do not automatically establish any Onym violation.

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

## 4. Mistral Moderation triage

### 4.1 What Mistral does

The Authority uses Mistral AI's text moderation service,
`mistral-moderation-2603`, as a first-pass classifier. Mistral documents that
the service returns category scores and classifications across categories such
as sexual content, hate and discrimination, violence and threats, dangerous
content, criminal content, self-harm, and personally identifying information.

For each eligible report, the Authority may use the returned scores and
Mistral's default policy thresholds to:

- prioritize urgent material;
- route a report to a reviewer with the relevant training;
- identify material requiring careful privacy handling; or
- identify reports that need manual triage because the model is uncertain or
  the Onym class does not map cleanly to a Mistral category.

The Authority records the model identifier and triage result used for the
report. Mistral states that its default thresholds are based on its internal
test set and that moderation models and scores may change. Scores are therefore
not stable facts about a person.

### 4.2 What Mistral does not do

Mistral does not:

- verify who authored the reported material;
- decide whether Onym's narrower class definition is satisfied;
- open a case or set a device mark;
- determine credibility, intent, consent, context, defenses, or sanctions;
- decide an appeal; or
- receive access to conversations that nobody reported.

A high score creates no presumption against the accused. A low score is not a
safe harbor. No ban may be based only on a Mistral result.

### 4.3 Errors and availability

Automated moderation can produce false positives and false negatives,
especially with quotation, reclaimed language, slang, satire, multilingual
content, or missing context. A Mistral outage or error does not count against a
reporter or accused. The Authority queues the report for manual triage or
declines intake without opening a case; it does not treat an error as proof of
a violation.

If the Authority changes the moderation provider, model family, or the role
automation plays in a case, the change must be disclosed in new terms and may
bind new mandates only after review and consent. If the named Mistral model is
unavailable for an existing mandate, the Authority may use human triage; it may
not silently replace it with another automated decision-maker.

## 5. What is sent to Mistral

Only text that a reporter deliberately includes in a report, plus the minimum
textual context needed to classify it, is eligible for Mistral triage. Before
submission, the Authority removes Onym identity keys, device bindings,
signatures, report and case identifiers, and reporter identity unless those
details are inseparable from the disclosed text itself.

Images, video, audio, cryptographic proofs, and device data are not submitted
to Mistral Moderation under these terms. Material that cannot safely or
lawfully be sent to a general text-classification service—including suspected
child sexual abuse media—is routed directly to the trained human and lawful
reporting process.

Mistral AI is therefore a third-party processor of the eligible text. Mistral's
current documentation says API data is not used for model training and offers
a zero-data-retention control. The Default Authority must keep training use
disabled and zero data retention enabled for moderation requests. If those
controls are unavailable, it must stop sending report text to Mistral and use
manual triage until the disclosed configuration is restored.

Mistral's current documentation is available at:

- [Moderation & Guardrailing](https://docs.mistral.ai/en/studio-api/conversations/moderation)
- [Privacy and data controls](https://docs.mistral.ai/admin/monitor-comply/privacy-data-controls)

These links explain Mistral's service; they do not let Mistral expand this
Authority's jurisdiction.

## 6. Case procedure

1. **Jurisdiction and authenticity.** The Authority verifies both parties'
   mandates, the claimed class, the report signature, and the evidence's
   authorship proof before treating the material as evidence.
2. **Triage.** Eligible text is minimized and sent to Mistral as described in
   §§4–5. A trained reviewer sees the triage result and the record.
3. **Human intake.** A person decides whether the report is within the class
   and sufficient to open a case. A receipt for a report is not notice that a
   case opened.
4. **Notice.** If a case opens, the interface shows the accused the class,
   intake basis, evidence available under the confidentiality rules, response
   deadline, and decision deadline. The procedural `case-open` mark does not
   reduce service.
5. **Response.** The accused may submit a signed statement and counter-evidence
   throughout the response window. Not responding is not a confession.
6. **Decision.** A human reviewer decides against the exact class definition
   in §2 and gives signed reasoning. No ban may issue before the response
   window closes or after the decision deadline.
7. **Default.** If the Authority does not decide by the deadline, the case is
   dismissed and the `case-open` mark clears.

## 7. Appeals and a device's new holder

An accused user may appeal within the period in §2. A successful appeal results
in a new signed reversal verdict; the original verdict is not edited.

A person who acquired a marked device from somebody else may make a
challenge-bound new-holder claim without possessing the former holder's
identity key. The interface must provide this route for as long as a device ban
is in force. The Authority expedites these claims because a device is not a
person.

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
- treat Mistral output as a verdict;
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
the disclosure of eligible reported text to Mistral AI for triage, and consent
to the Authority and classes above for this identity and device.
