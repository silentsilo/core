// Without `hardware` every entry point in lib.rs answers NotAvailable itself;
// this is the one call it forwards unconditionally.
pub(crate) fn wait_for_ceremony_teardown(_timeout_ms: u64) {}
