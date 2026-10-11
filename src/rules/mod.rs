//! Evaluates rules against one object at a time and emits [`Finding`]s.
//!
//! Single responsibility: decide whether a single [`ObjectMeta`] violates
//! anything. The rule engine never looks across objects, never counts, and
//! never reads the network.
//!
//! **Memory budget: 2 MB.** Evaluation is stateless per object: a rule sees
//! one [`ObjectMeta`], returns zero or more [`Finding`]s, and retains nothing.
//! Accumulation across objects is [`crate::aggregate`]'s job, not this
//! module's.
//!
//! [`ObjectMeta`]: crate::model::ObjectMeta
//! [`Finding`]: crate::model::Finding
