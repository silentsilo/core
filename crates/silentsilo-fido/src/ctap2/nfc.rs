//! CTAP2 over NFC: ISO 7816 APDUs to the FIDO applet, chained when a
//! command is longer than a short APDU carries.

use super::{Ctap, CtapError, split_status};

/// Sends one APDU and returns the response data followed by SW1 SW2.
pub trait Apdu {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CtapError>;
}

const FIDO_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
const SW_OK: u16 = 0x9000;
/// The key is still working and wants to be asked again.
const SW_KEEPALIVE: u16 = 0x9100;
/// How long a key may keep asking to wait, as over USB.
const KEEPALIVE_LIMIT: std::time::Duration = std::time::Duration::from_secs(45);

pub struct Nfc<A: Apdu> {
    link: A,
    selected: bool,
}

impl<A: Apdu> Nfc<A> {
    pub fn new(link: A) -> Self {
        Self {
            link,
            selected: false,
        }
    }

    /// One command, chained in 255-byte pieces, with every `61xx` fetched.
    fn exchange(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        data: &[u8],
    ) -> Result<(Vec<u8>, u16), CtapError> {
        let pieces: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(255).collect()
        };
        let mut answer = Vec::new();
        let mut sw = 0;
        for (i, piece) in pieces.iter().enumerate() {
            let last = i + 1 == pieces.len();
            let mut apdu = vec![if last { cla } else { cla | 0x10 }, ins, p1, 0x00];
            if !piece.is_empty() {
                apdu.push(piece.len() as u8);
                apdu.extend_from_slice(piece);
            }
            if last {
                apdu.push(0x00);
            }
            (answer, sw) = self.send(&apdu)?;
            if !last && sw != SW_OK {
                return Err(CtapError::Protocol(format!("chaining refused ({sw:04x})")));
            }
        }
        let mut rounds = 0;
        while sw >> 8 == 0x61 {
            // A CTAP answer is a few kilobytes; a key that keeps offering
            // more is not answering.
            rounds += 1;
            if rounds > 64 {
                return Err(CtapError::Protocol("the answer does not end".into()));
            }
            let (more, next) = self.send(&[0x00, 0xC0, 0x00, 0x00, sw as u8])?;
            answer.extend_from_slice(&more);
            sw = next;
        }
        Ok((answer, sw))
    }

    fn send(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), CtapError> {
        let mut response = self.link.transmit(apdu)?;
        if response.len() < 2 {
            return Err(CtapError::Protocol(
                "a response without a status word".into(),
            ));
        }
        let sw = u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]]);
        response.truncate(response.len() - 2);
        Ok((response, sw))
    }

    fn select(&mut self) -> Result<(), CtapError> {
        let (_, sw) = self.exchange(0x00, 0xA4, 0x04, &FIDO_AID)?;
        if sw != SW_OK {
            return Err(CtapError::Unsupported("it has no FIDO applet".into()));
        }
        self.selected = true;
        Ok(())
    }
}

impl<A: Apdu> Ctap for Nfc<A> {
    fn command(&mut self, command: u8, cbor: &[u8]) -> Result<Vec<u8>, CtapError> {
        if !self.selected {
            self.select()?;
        }
        let mut payload = Vec::with_capacity(cbor.len() + 1);
        payload.push(command);
        payload.extend_from_slice(cbor);
        // P1 0x80: this side answers keep-alives with NFCCTAP_GETRESPONSE.
        let (mut answer, mut sw) = self.exchange(0x80, 0x10, 0x80, &payload)?;
        let started = std::time::Instant::now();
        while sw == SW_KEEPALIVE {
            if started.elapsed() > KEEPALIVE_LIMIT {
                return Err(CtapError::Timeout);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            (answer, sw) = self.exchange(0x80, 0x11, 0x00, &[])?;
        }
        if sw != SW_OK {
            return Err(CtapError::Protocol(format!("status word {sw:04x}")));
        }
        split_status(answer)
    }
}
