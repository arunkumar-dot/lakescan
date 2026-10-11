//! Evaluates rules against one object at a time and emits [`Finding`]s.
//!
//! Single responsibility: decide whether a single [`ObjectMeta`] violates
//! anything. The rule engine never looks across objects, never counts, and
//! never reads the network.
//!
//! **Memory budget: 2 MB.** Evaluation is stateless per object: a rule sees
//! one [`ObjectMeta`], returns zero or more [`Finding`]s, and retains
//! nothing. Rules allocate nothing per object, either: no `to_lowercase`,
//! `format!`, `String`, or `Vec`. Case-insensitive key matching is done with
//! `eq_ignore_ascii_case` on `&str` slices obtained from `str::get` with
//! checked arithmetic, never by indexing or by building an owned lowercase
//! copy. Accumulation across objects is [`crate::aggregate`]'s job, not this
//! module's.
//!
//! [`Severity::Critical`] is unused by every v1 rule. Nothing a
//! `ListObjectsV2` listing reports — key, size, timestamp, storage class —
//! can prove an object is *actually* exposed right now; that needs bucket
//! policy, ACLs, or Block Public Access settings, none of which this
//! milestone fetches. Every v1 finding tops out at [`Severity::High`].
//!
//! [`ObjectMeta`]: crate::model::ObjectMeta
//! [`Finding`]: crate::model::Finding
//! [`Severity::Critical`]: crate::model::Severity::Critical
//! [`Severity::High`]: crate::model::Severity::High

mod reduced_redundancy;
mod sensitive_key;
mod small_object_cold_tier;
mod stale_standard;
mod unknown_storage_class;
mod zero_byte_object;

use std::time::SystemTime;

use crate::model::{Finding, ObjectMeta, RuleId, Severity};

/// Everything a rule is allowed to know besides the object itself.
///
/// Rules read time only through [`EvalContext::now`], never through
/// [`SystemTime::now`] directly: injecting "now" is what makes age-based
/// rules (see `stale_standard`) deterministic and testable without a clock.
#[derive(Debug, Clone, Copy)]
pub struct EvalContext {
    /// The instant "now" means, for every age computation in this
    /// evaluation run.
    pub now: SystemTime,
}

/// The signature every rule's check function has: a pure function from one
/// object and the shared context to at most one severity. No rule may
/// return more than one finding for itself.
type Check = fn(&ObjectMeta, &EvalContext) -> Option<Severity>;

/// Looks up the check function for a [`RuleId`].
///
/// This is the one `match` in the crate that must stay exhaustive over
/// [`RuleId`]: adding a rule variant without adding its arm here is a
/// compile error, not a silently-skipped rule.
fn check_for(rule: RuleId) -> Check {
    match rule {
        RuleId::SensitiveKey => sensitive_key::check,
        RuleId::ReducedRedundancy => reduced_redundancy::check,
        RuleId::StaleStandard => stale_standard::check,
        RuleId::SmallObjectColdTier => small_object_cold_tier::check,
        RuleId::ZeroByteObject => zero_byte_object::check,
        RuleId::UnknownStorageClass => unknown_storage_class::check,
    }
}

/// Evaluates every rule against `object`, in [`RuleId::ALL`] order.
///
/// Lazy and allocation-free: this is an iterator over [`RuleId::ALL`] that
/// runs each rule's check on demand and yields a [`Finding`] only where one
/// fired. Every yielded [`Finding`] borrows `object`, so none of them can
/// outlive it.
pub fn evaluate<'a>(
    object: &'a ObjectMeta,
    ctx: &'a EvalContext,
) -> impl Iterator<Item = Finding<'a>> + 'a {
    RuleId::ALL.into_iter().filter_map(move |rule| {
        check_for(rule)(object, ctx).map(|severity| Finding {
            rule,
            severity,
            object,
        })
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{EvalContext, evaluate};
    use crate::model::{ObjectMeta, RuleId, StorageClass};

    /// A clean baseline object that no v1 rule should flag: a normal-sized
    /// `STANDARD` object with an unremarkable key, last modified recently.
    fn clean_object(ctx: &EvalContext) -> ObjectMeta {
        ObjectMeta {
            key: "reports/2024/summary.csv".to_owned(),
            size: 1024 * 1024,
            last_modified: ctx.now,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        }
    }

    fn ctx() -> EvalContext {
        EvalContext {
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000),
        }
    }

    #[test]
    fn a_clean_object_yields_no_findings() {
        let ctx = ctx();
        let object = clean_object(&ctx);

        assert_eq!(evaluate(&object, &ctx).count(), 0);
    }

    #[test]
    fn an_object_violating_several_rules_yields_them_in_rule_id_all_order() {
        let ctx = ctx();
        // Zero bytes (ZeroByteObject), key looks like an SSH key (SensitiveKey),
        // and the storage class is unrecognized (UnknownStorageClass) all at
        // once, in a single object.
        let object = ObjectMeta {
            key: ".ssh/id_rsa".to_owned(),
            size: 0,
            last_modified: ctx.now,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Other("NEW_CLASS".to_owned()),
        };

        let rules: Vec<RuleId> = evaluate(&object, &ctx)
            .map(|finding| finding.rule)
            .collect();

        assert_eq!(
            rules,
            [
                RuleId::SensitiveKey,
                RuleId::ZeroByteObject,
                RuleId::UnknownStorageClass,
            ]
        );
    }

    #[test]
    fn every_rule_id_has_at_least_one_object_that_triggers_it() {
        let ctx = EvalContext {
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000_000),
        };

        let triggering_objects = [
            ObjectMeta {
                key: "id_rsa".to_owned(),
                size: 1024,
                last_modified: ctx.now,
                etag: "etag".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "data.bin".to_owned(),
                size: 1024,
                last_modified: ctx.now,
                etag: "etag".to_owned(),
                storage_class: StorageClass::ReducedRedundancy,
            },
            ObjectMeta {
                key: "big/old.bin".to_owned(),
                size: 2 * 1024 * 1024 * 1024,
                last_modified: SystemTime::UNIX_EPOCH,
                etag: "etag".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "small/cold.bin".to_owned(),
                size: 100,
                last_modified: ctx.now,
                etag: "etag".to_owned(),
                storage_class: StorageClass::Glacier,
            },
            ObjectMeta {
                key: "empty.bin".to_owned(),
                size: 0,
                last_modified: ctx.now,
                etag: "etag".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "mystery.bin".to_owned(),
                size: 1024,
                last_modified: ctx.now,
                etag: "etag".to_owned(),
                storage_class: StorageClass::Other("NEW_CLASS".to_owned()),
            },
        ];

        for rule in RuleId::ALL {
            let triggered = triggering_objects
                .iter()
                .any(|object| evaluate(object, &ctx).any(|finding| finding.rule == rule));
            assert!(triggered, "no test object triggers {rule:?}");
        }
    }
}
