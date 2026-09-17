//! Certificate checks for S3 and WebDAV over HTTPS: the operating system's
//! verifier, the same one for both. On Android it calls into the JVM, so the
//! app hands it the runtime first with [`init_android_tls`]; until then a
//! handshake fails with [`NOT_INITIALISED`] instead of panicking.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

/// What a handshake reports when the app never set up the verifier.
pub const NOT_INITIALISED: &str =
    "secure connections are not set up in this app yet (init_android_tls was not called)";

#[cfg(target_os = "android")]
static READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the verifier can run. Always on desktop, which needs no setup.
pub fn ready() -> bool {
    #[cfg(target_os = "android")]
    {
        READY.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(not(target_os = "android"))]
    {
        true
    }
}

/// Gives the platform verifier the JVM and the application context. Call once
/// from the app's JNI entry point, before any sync; later calls do nothing.
/// The app must also ship the `rustls:rustls-platform-verifier` Kotlin
/// component (see the README).
///
/// # Safety
///
/// `env` must be the `JNIEnv` of the current, attached thread and `context`
/// a live local or global reference to an Android `Context`, both valid for
/// the duration of the call.
#[cfg(target_os = "android")]
pub unsafe fn init_android_tls(
    env: *mut std::ffi::c_void,
    context: *mut std::ffi::c_void,
) -> Result<(), String> {
    if env.is_null() || context.is_null() {
        return Err("init_android_tls needs a JNIEnv and a Context".into());
    }
    // Raw pointers, so the app is free to use any jni release.
    let mut unowned = unsafe { jni::EnvUnowned::from_raw(env.cast()) };
    let outcome = unowned
        .with_env(|env| -> Result<(), jni::errors::Error> {
            let context = unsafe { jni::objects::JObject::from_raw(env, context.cast()) };
            rustls_platform_verifier::android::init_with_env(env, context)
        })
        .into_outcome();
    match outcome {
        jni::Outcome::Ok(()) => {
            READY.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        jni::Outcome::Err(e) => Err(format!("could not set up certificate checks: {e}")),
        jni::Outcome::Panic(_) => Err("could not set up certificate checks".into()),
    }
}

/// A TLS client configuration that checks certificates with the platform
/// verifier, refusing every handshake while [`ready`] is false.
pub fn client_config() -> Result<rustls::ClientConfig, String> {
    guarded_config(ready)
}

fn guarded_config(ready: fn() -> bool) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let inner = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|e| format!("certificate checks: {e}"))?;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Guarded { inner, ready }))
        .with_no_client_auth())
}

/// The platform verifier behind a readiness check: on Android an
/// uninitialised verifier panics inside the handshake.
#[derive(Debug)]
struct Guarded<V> {
    inner: V,
    ready: fn() -> bool,
}

impl<V: ServerCertVerifier> ServerCertVerifier for Guarded<V> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !(self.ready)() {
            return Err(rustls::Error::General(NOT_INITIALISED.into()));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Panics like the Android verifier does before it is initialised.
    #[derive(Debug)]
    struct Uninitialised;

    impl ServerCertVerifier for Uninitialised {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            panic!("Expect rustls-platform-verifier to be initialized")
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            unreachable!()
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            unreachable!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    fn check(verifier: &dyn ServerCertVerifier) -> Result<ServerCertVerified, rustls::Error> {
        verifier.verify_server_cert(
            &CertificateDer::from(vec![0u8; 4]),
            &[],
            &ServerName::try_from("example.com").unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    #[test]
    fn a_verifier_not_set_up_refuses_instead_of_panicking() {
        let guarded = Guarded {
            inner: Uninitialised,
            ready: || false,
        };
        match check(&guarded) {
            Err(rustls::Error::General(message)) => assert_eq!(message, NOT_INITIALISED),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(
            guarded.supported_verify_schemes(),
            vec![SignatureScheme::ED25519]
        );
    }

    #[test]
    fn a_ready_verifier_is_asked() {
        let guarded = Guarded {
            inner: Uninitialised,
            ready: || true,
        };
        let asked = std::panic::catch_unwind(|| check(&guarded));
        assert!(asked.is_err(), "the inner verifier decides once ready");
    }

    #[test]
    fn desktop_needs_no_setup_and_rejects_a_bogus_certificate() {
        assert!(ready());
        client_config().expect("builds on desktop");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let guarded = Guarded {
            inner: rustls_platform_verifier::Verifier::new(provider).unwrap(),
            ready,
        };
        assert!(check(&guarded).is_err());
    }
}
