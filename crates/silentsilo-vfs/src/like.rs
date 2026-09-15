//! Patterns built from paths and text the user chose. Every subtree
//! operation asks which rows live under a folder, and `path GLOB
//! '/parent/*'` is only correct while the folder's name has no wildcard in
//! it. Names may contain them: `%`, `*`, `?` and `[` are allowed, and `_` is
//! *produced* by `sanitize` for every character Windows forbids. Unescaped,
//! such a folder matches its neighbours and purge takes their blobs with it
//! on every device.
//!
//! Subtrees use `GLOB`, which compares case for case. `LIKE` folds ASCII
//! case, and folders "x (2)" and "X (2)" can sit side by side, so a purge of
//! one took the other's contents. Search still uses `LIKE ... ESCAPE '!'`,
//! where folding case is the point.
//!
//! So no query builds a pattern by hand: use the helpers here.

/// Everything strictly below `path`, with the path itself taken literally,
/// for `path GLOB ?`.
///
/// A trailing separator on the input is ignored, so the root (`/`) yields
/// `/*` and matches the whole tree rather than nothing.
pub(crate) fn subtree(path: &str) -> String {
    format!("{}/*", glob_escape(path.trim_end_matches('/')))
}

/// Everything below a prefix that already carries its trailing separator,
/// for `path GLOB ?`.
///
/// Separate from [`subtree`] because rename needs the prefix itself as well,
/// to compute how much of each descendant path to replace, and building it
/// twice from different halves is how the two drift apart.
pub(crate) fn below_prefix(prefix: &str) -> String {
    format!("{}*", glob_escape(prefix))
}

/// Anything containing `text`, for search: `LIKE ? ESCAPE '!'`.
pub(crate) fn containing(text: &str) -> String {
    format!("%{}%", escape(text))
}

/// Neutralises the three characters `LIKE ... ESCAPE '!'` treats specially.
///
/// The escape character has to come first, or it would be applied again to
/// the markers the other two replacements just inserted.
fn escape(text: &str) -> String {
    text.replace('!', "!!")
        .replace('%', "!%")
        .replace('_', "!_")
}

/// `GLOB` has no escape character: a wildcard is made literal by putting it
/// in a one-character class. `]` needs nothing outside a class.
fn glob_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '*' | '?' | '[' => {
                out.push('[');
                out.push(c);
                out.push(']');
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_in_a_folder_name_stay_literal() {
        assert_eq!(subtree("/a*b"), "/a[*]b/*");
        assert_eq!(subtree("/a?b[1]"), "/a[?]b[[]1]/*");
        assert_eq!(below_prefix("/a*b/"), "/a[*]b/*");
        // LIKE's wildcards mean nothing to GLOB.
        assert_eq!(subtree("/a%b_c"), "/a%b_c/*");
    }

    #[test]
    fn the_escape_character_escapes_itself() {
        // Escaping `!` last would turn the `!` of `!%` into `!!%`, which
        // matches a literal `!` followed by anything.
        assert_eq!(containing("a!b"), "%a!!b%");
        assert_eq!(containing("a!%b"), "%a!!!%b%");
    }

    #[test]
    fn the_root_matches_the_whole_tree() {
        assert_eq!(subtree("/"), "/*");
    }

    #[test]
    fn an_ordinary_path_is_left_alone() {
        assert_eq!(subtree("/photos/2026"), "/photos/2026/*");
        assert_eq!(containing("report"), "%report%");
    }

    #[test]
    fn a_subtree_matches_case_for_case_and_wildcards_literally() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let hits = |pattern: &str, path: &str| -> bool {
            conn.query_row("SELECT ?2 GLOB ?1", [pattern, path], |r| r.get(0))
                .unwrap()
        };
        assert!(hits(&subtree("/x (2)"), "/x (2)/sub"));
        assert!(!hits(&subtree("/x (2)"), "/X (2)/sub"));
        assert!(!hits(&subtree("/a*"), "/abc/sub"));
        assert!(hits(&subtree("/a*"), "/a*/sub"));
        assert!(!hits(&subtree("/a[1]"), "/a1/sub"));
        assert!(hits(&subtree("/a[1]"), "/a[1]/sub"));
        assert!(!hits(&subtree("/Work"), "/Workshop/x"));
    }
}
