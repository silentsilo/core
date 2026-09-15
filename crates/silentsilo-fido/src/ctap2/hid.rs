//! CTAP2 over USB: CTAPHID messages in 64-byte reports, on a channel the
//! key hands out at `INIT`.

use std::time::{Duration, Instant};

use rand::RngCore;

use super::{Ctap, CtapError, split_status};

pub const REPORT_LEN: usize = 64;

/// The key's HID endpoints: reports without a report id.
pub trait Reports {
    fn write(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), CtapError>;
    /// `None` when nothing arrived within `timeout_ms`.
    fn read(&mut self, timeout_ms: u32) -> Result<Option<[u8; REPORT_LEN]>, CtapError>;
}

const BROADCAST: [u8; 4] = [0xff; 4];
const CMD_INIT: u8 = 0x86;
const CMD_CBOR: u8 = 0x90;
const CMD_KEEPALIVE: u8 = 0xBB;
const CMD_ERROR: u8 = 0xBF;

/// How long a command may take, the touch included. Keys give up on the
/// touch sooner and say so.
const COMMAND_LIMIT: Duration = Duration::from_secs(45);

pub struct Hid<R: Reports> {
    link: R,
    channel: Option<[u8; 4]>,
}

impl<R: Reports> Hid<R> {
    pub fn new(link: R) -> Self {
        Self {
            link,
            channel: None,
        }
    }

    fn write_message(&mut self, cid: [u8; 4], cmd: u8, data: &[u8]) -> Result<(), CtapError> {
        let mut report = [0u8; REPORT_LEN];
        report[..4].copy_from_slice(&cid);
        report[4] = cmd;
        report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let first = data.len().min(REPORT_LEN - 7);
        report[7..7 + first].copy_from_slice(&data[..first]);
        self.link.write(&report)?;
        for (seq, piece) in data[first..].chunks(REPORT_LEN - 5).enumerate() {
            let mut report = [0u8; REPORT_LEN];
            report[..4].copy_from_slice(&cid);
            report[4] = seq as u8;
            report[5..5 + piece.len()].copy_from_slice(piece);
            self.link.write(&report)?;
        }
        Ok(())
    }

    /// The next message on `cid` other than a keep-alive.
    fn read_message(&mut self, cid: [u8; 4]) -> Result<(u8, Vec<u8>), CtapError> {
        let deadline = Instant::now() + COMMAND_LIMIT;
        let next = |link: &mut R| -> Result<[u8; REPORT_LEN], CtapError> {
            loop {
                if Instant::now() > deadline {
                    return Err(CtapError::Timeout);
                }
                if let Some(report) = link.read(250)?
                    && report[..4] == cid
                {
                    return Ok(report);
                }
            }
        };
        loop {
            let report = next(&mut self.link)?;
            let cmd = report[4];
            if cmd == CMD_KEEPALIVE {
                continue;
            }
            if cmd & 0x80 == 0 {
                // A continuation with no message started: stale, skipped.
                continue;
            }
            let len = u16::from_be_bytes([report[5], report[6]]) as usize;
            let mut data = report[7..7 + len.min(REPORT_LEN - 7)].to_vec();
            let mut seq = 0u8;
            while data.len() < len {
                let more = next(&mut self.link)?;
                if more[4] != seq {
                    return Err(CtapError::Protocol("a report out of sequence".into()));
                }
                seq = seq.wrapping_add(1);
                let take = (len - data.len()).min(REPORT_LEN - 5);
                data.extend_from_slice(&more[5..5 + take]);
            }
            if cmd == CMD_ERROR {
                return Err(CtapError::Protocol(format!(
                    "CTAPHID error {:#04x}",
                    data.first().copied().unwrap_or(0)
                )));
            }
            return Ok((cmd, data));
        }
    }

    fn channel(&mut self) -> Result<[u8; 4], CtapError> {
        if let Some(cid) = self.channel {
            return Ok(cid);
        }
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);
        self.write_message(BROADCAST, CMD_INIT, &nonce)?;
        loop {
            let (cmd, data) = self.read_message(BROADCAST)?;
            if cmd == CMD_INIT && data.len() >= 17 && data[..8] == nonce {
                let cid: [u8; 4] = data[8..12].try_into().expect("four bytes");
                self.channel = Some(cid);
                return Ok(cid);
            }
        }
    }
}

impl<R: Reports> Ctap for Hid<R> {
    fn command(&mut self, command: u8, cbor: &[u8]) -> Result<Vec<u8>, CtapError> {
        let cid = self.channel()?;
        let mut payload = Vec::with_capacity(cbor.len() + 1);
        payload.push(command);
        payload.extend_from_slice(cbor);
        self.write_message(cid, CMD_CBOR, &payload)?;
        let (cmd, data) = self.read_message(cid)?;
        if cmd != CMD_CBOR {
            return Err(CtapError::Protocol(format!(
                "unexpected CTAPHID reply {cmd:#04x}"
            )));
        }
        split_status(data)
    }
}
