//! Process-wide settings that keep what is in memory out of files.

/// Turns off core dumps for this process: a crash while a silo is open
/// would otherwise write its keys and decrypted pages to disk. On Linux the
/// process is also marked not dumpable, which keeps other programs of the
/// same user from attaching a debugger to it. Call once, first thing at
/// startup. Returns whether every setting took. Windows writes no dump
/// unless Windows Error Reporting is set up to, and changes nothing here.
pub fn harden_process() -> bool {
    #[allow(unused_mut)]
    let mut ok = true;
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a valid pointer to a live struct for the call.
        ok &= unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } == 0;
    }
    // Not on Android, where the system's own crash reports need it.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes plain integers.
        ok &= unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    }
    ok
}

#[cfg(test)]
mod tests {
    /// Run in a child process, since the settings are for good.
    #[cfg(unix)]
    #[test]
    fn core_dumps_are_off_afterwards() {
        if std::env::var_os("SILENTSILO_HARDEN_CHILD").is_some() {
            assert!(super::harden_process());
            let mut limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: a valid out-pointer.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
            assert_eq!(limit.rlim_cur, 0);
            #[cfg(target_os = "linux")]
            // SAFETY: as above.
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process::tests::core_dumps_are_off_afterwards"])
            .env("SILENTSILO_HARDEN_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(not(unix))]
    #[test]
    fn nothing_to_do_here_is_not_a_failure() {
        assert!(super::harden_process());
    }
}
