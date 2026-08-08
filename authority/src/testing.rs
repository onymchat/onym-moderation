//! Fixtures shared by the unit tests.
#![cfg(test)]

/// A manifest that satisfies the consent-time conditions the interface
/// checks: a supported profile, an external appellate for its permanent
/// class, and a new-holder path.
pub const MANIFEST_JSON: &str = r#"{
  "version": 1,
  "componentId": "onym:component:test-authority",
  "seat": "moderation",
  "operator": "onym:key:0000000000000000000000000000000000000000000000000000000000000000",
  "moderationProfileId": "onym:moderation-profile:consent-bound-v1",
  "violationClasses": [
    {
      "classId": "csam",
      "definition": "hash:csam",
      "responseWindow": "P3D",
      "decisionDeadline": "P7D",
      "banTerm": "permanent",
      "appealWindow": "P30D",
      "appealEffect": "non-suspensive"
    },
    {
      "classId": "unsolicited-pornography",
      "definition": "hash:up",
      "responseWindow": "P7D",
      "decisionDeadline": "P14D",
      "banTerm": "P90D",
      "appealWindow": "P30D",
      "appealEffect": "suspensive"
    }
  ],
  "newHolderAppeal": "hash:new-holder",
  "appellate": "onym:component:test-appellate",
  "validUntil": "2030-01-01T00:00:00Z"
}"#;
