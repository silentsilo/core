//! The first connections of a process, opened at once from many threads,
//! all have SQLCipher's `sqlcipher_export`. Its own test binary, so nothing
//! has opened a connection before it.

use std::sync::{Arc, Barrier};

#[test]
fn every_first_connection_has_sqlcipher_export() {
    const THREADS: usize = 64;
    let start = Arc::new(Barrier::new(THREADS));
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                silentsilo_vault::init_openssl();
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                conn.execute_batch("ATTACH DATABASE ':memory:' AS copy KEY '';")
                    .unwrap();
                conn.query_row("SELECT sqlcipher_export('copy')", [], |_| Ok(()))
                    .map_err(|e| e.to_string())
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap().unwrap();
    }
}
