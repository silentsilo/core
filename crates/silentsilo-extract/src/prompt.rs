//! Reading the recovery code without leaving it anywhere: typed at a prompt
//! that does not echo it, or piped in on standard input. On the command
//! line it would stay in the shell's history and show in the list of
//! running programs for as long as the extraction runs.

use std::io::{BufRead, IsTerminal, Write};

use zeroize::Zeroizing;

/// Asks for the code on the terminal with echo off, or reads the first line
/// of standard input when that is not a terminal.
pub fn read_code() -> Result<Zeroizing<String>, String> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return first_line(&mut stdin.lock());
    }
    eprint!("Recovery code (not shown as you type): ");
    let _ = std::io::stderr().flush();
    let echo = EchoOff::new();
    let code = first_line(&mut stdin.lock());
    drop(echo);
    eprintln!();
    code
}

/// Whether this process has a console window of its own: on Windows, one
/// started by a double-click in Explorer, whose window closes the moment the
/// process ends. Elsewhere a terminal outlives the tool.
pub fn console_closes_on_exit() -> bool {
    #[cfg(windows)]
    {
        let mut ids = [0u32; 2];
        // SAFETY: the buffer is ours and its length is passed with it.
        let attached = unsafe { windows::Win32::System::Console::GetConsoleProcessList(&mut ids) };
        attached == 1
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Holds a window that would close on exit until Enter is pressed, so what
/// was printed can be read.
pub fn wait_before_closing() {
    if console_closes_on_exit() {
        eprint!(
            "
Press Enter to close this window."
        );
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
    }
}

fn first_line(input: &mut impl BufRead) -> Result<Zeroizing<String>, String> {
    let mut line = Zeroizing::new(String::new());
    input
        .read_line(&mut line)
        .map_err(|e| format!("Could not read the recovery code: {e}"))?;
    let code = Zeroizing::new(line.trim().to_string());
    if code.is_empty() {
        return Err("No recovery code was given.".into());
    }
    Ok(code)
}

/// Terminal echo turned off until this is dropped.
struct EchoOff {
    #[cfg(unix)]
    saved: Option<libc::termios>,
    #[cfg(windows)]
    saved: Option<(
        windows::Win32::Foundation::HANDLE,
        windows::Win32::System::Console::CONSOLE_MODE,
    )>,
}

impl EchoOff {
    #[cfg(unix)]
    fn new() -> Self {
        // SAFETY: plain calls on the standard input descriptor with a
        // termios this function owns.
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut term) != 0 {
                return Self { saved: None };
            }
            let saved = term;
            term.c_lflag &= !libc::ECHO;
            term.c_lflag |= libc::ECHONL;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) != 0 {
                return Self { saved: None };
            }
            Self { saved: Some(saved) }
        }
    }

    #[cfg(windows)]
    fn new() -> Self {
        use windows::Win32::System::Console::{
            CONSOLE_MODE, ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
            SetConsoleMode,
        };
        // SAFETY: the standard input handle, and a mode this function owns.
        unsafe {
            let Ok(handle) = GetStdHandle(STD_INPUT_HANDLE) else {
                return Self { saved: None };
            };
            let mut mode = CONSOLE_MODE::default();
            if GetConsoleMode(handle, &mut mode).is_err() {
                return Self { saved: None };
            }
            if SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT).is_err() {
                return Self { saved: None };
            }
            Self {
                saved: Some((handle, mode)),
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(saved) = self.saved.take() {
            // SAFETY: restores the settings read in `new`.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved);
            }
        }
        #[cfg(windows)]
        if let Some((handle, mode)) = self.saved.take() {
            // SAFETY: restores the mode read in `new`, on the same handle.
            unsafe {
                let _ = windows::Win32::System::Console::SetConsoleMode(handle, mode);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_piped_code_is_its_first_line_trimmed() {
        let mut input = std::io::Cursor::new("  ABCD-EFGH \nsomething else\n");
        assert_eq!(first_line(&mut input).unwrap().as_str(), "ABCD-EFGH");
    }

    #[test]
    fn nothing_piped_is_an_error_not_an_empty_code() {
        let mut input = std::io::Cursor::new("\n");
        assert!(first_line(&mut input).is_err());
        let mut input = std::io::Cursor::new("");
        assert!(first_line(&mut input).is_err());
    }
}
