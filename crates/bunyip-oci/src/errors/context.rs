//! The one place a failure inside this vertical becomes [`OciError::Internal`].
//!
//! The OCI distribution spec pins the wire vocabulary, so every fault here has
//! to collapse into one coarse variant and the cause cannot travel with it. The
//! collapse therefore happens HERE and logs first, naming the operation, so a
//! registry 500 is diagnosable from the API log alone (BUNYIP-565).

use std::fmt::Display;

use super::OciError;

/// Report an internal fault that carries no error value and return the wire
/// error. For a wiring gap (a service missing from the app data, an
/// unconfigured cache) where the failure IS the absence: `ok_or_else(|| ...)`.
pub fn internal_fault(operation: &str) -> OciError {
    tracing::error!(operation, "oci internal fault");
    OciError::Internal
}

/// Map a fallible call to [`OciError::Internal`], logging its cause first.
pub trait OciErrorContext<T> {
    /// `operation` names what was being attempted, including the identifiers in
    /// scope (slug, digest, user id). It is a closure so the happy path pays no
    /// formatting cost.
    fn internal_ctx<F, D>(self, operation: F) -> Result<T, OciError>
    where
        F: FnOnce() -> D,
        D: Display;
}

impl<T, E: Display> OciErrorContext<T> for Result<T, E> {
    fn internal_ctx<F, D>(self, operation: F) -> Result<T, OciError>
    where
        F: FnOnce() -> D,
        D: Display,
    {
        match self {
            Ok(value) => Ok(value),
            Err(e) => {
                tracing::error!(error = %e, operation = %operation(), "oci internal error");
                Err(OciError::Internal)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_ctx_keeps_the_variant_and_passes_success_through() {
        let ok: Result<u8, String> = Ok(7);
        assert_eq!(ok.internal_ctx(|| "unused").expect("passes through"), 7);

        let err: Result<u8, String> = Err("pool exhausted".into());
        assert!(matches!(
            err.internal_ctx(|| format!("load user {}", 1)),
            Err(OciError::Internal)
        ));
        assert!(matches!(
            internal_fault("no token service"),
            OciError::Internal
        ));
    }

    /// BUNYIP-565: no failure in this vertical reaches the client as a bare
    /// `OciError::Internal` with its cause dropped. Two shapes fail the build:
    /// a discarding `map_err`, anywhere under `crates/bunyip-oci/src`, and an
    /// `OciError::Internal` built outside this module, which is the only place
    /// that logs before returning it. Scanned by walking the source tree, so a
    /// new file cannot escape the rule by not being listed here.
    #[test]
    fn every_internal_error_logs_its_cause_first() {
        fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("readable dir") {
                let path = entry.expect("readable entry").path();
                if path.is_dir() {
                    sources(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&src, &mut files);
        assert!(files.len() > 1, "the scan found no sources to check");

        // Both needles are assembled rather than written out, so this test's own
        // text is not a hit for the shapes it forbids.
        let discarding = ["map_err(|", "_|"].concat();
        let internal = ["OciError", "::Internal"].concat();

        let mut violations = Vec::new();
        let mut helper_uses = 0usize;
        for file in &files {
            let source = std::fs::read_to_string(file).expect("readable source");
            let name = file.display().to_string();
            if source.contains(&discarding) {
                violations.push(format!(
                    "{name}: discards the error with a `{discarding}` closure"
                ));
            }
            if file.file_name().is_some_and(|n| n == "context.rs") {
                continue;
            }
            helper_uses +=
                source.matches("internal_ctx(").count() + source.matches("internal_fault(").count();
            if source.contains(&internal) {
                violations.push(format!(
                    "{name}: builds `{internal}` directly; go through \
                     internal_ctx / internal_fault so the cause is logged"
                ));
            }
        }

        assert!(
            violations.is_empty(),
            "every failure that becomes an OciError logs its cause first \
             (BUNYIP-565): {violations:#?}"
        );
        assert!(
            helper_uses > 1,
            "the scan found no call site using the helpers; the pattern has drifted"
        );
    }
}
