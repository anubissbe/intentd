//! Harness v2.7 teaches provider-neutral writes and GitLab CLI boundaries.
use super::{Doctrine, HarnessEntry};
static DOCTRINE: Doctrine = Doctrine {
    instructions: &crate::instructions::V2_7,
    specialists: crate::specialists::EMBEDDED_BUNDLED_V2_5,
};
pub(crate) static ENTRY: HarnessEntry = HarnessEntry {
    version: "2.7",
    harness: &super::v2_4::V2_4,
    doctrine: &DOCTRINE,
    default_features: intent_core::settings_file::AgentFeaturesSettings::default,
    feature_labels: super::v1::FEATURE_LABELS,
};
