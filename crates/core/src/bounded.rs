//! Bounded capture of file contents and command output (#19).
//!
//! `read` used to call `read_to_string` on the whole file and `bash` used to
//! call `wait_with_output`, so both buffered everything before truncating to
//! 30,000 bytes (PLAN 6.4). A large file or a `yes` loop could exhaust memory
//! long before the timeout. The helpers here keep a fixed-size head and tail
//! plus a running total — all `truncate` ever shows the model — and stop
//! reading a stream once it has passed the capture limit.

use std::collections::VecDeque;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::context::truncate::{truncation_marker, HEAD_BYTES, TAIL_BYTES};

/// Files up to this size are read whole. The numbered output of a larger file
/// is always truncated, so buffering more would only cost memory.
pub(crate) const READ_ALL_MAX: u64 = 64 * 1024;

/// Larger files are refused instead of scanned: counting lines through them
/// would stall the turn for output the model never sees.
pub(crate) const READ_LIMIT: u64 = 16 * 1024 * 1024;

/// Bytes of one bash stream captured before the command is killed.
pub(crate) const STREAM_LIMIT: u64 = 8 * 1024 * 1024;

/// The window size used when reading a chunk of a file.
const CHUNK: usize = 64 * 1024;

/// Why a bounded read returned no content.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// The file is above [`READ_LIMIT`], so it was not read at all.
    TooLarge {
        len: u64,
    },
    Io(io::Error),
}

impl From<io::Error> for ReadError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { len } => write!(
                f,
                "{len} bytes is over the {READ_LIMIT}-byte read limit; \
                 inspect it with bash (head, tail, grep) instead"
            ),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

/// Read `path` with line numbers, buffering at most a head and a tail window.
///
/// Files up to [`READ_ALL_MAX`] behave exactly like a whole-file read: the
/// numbered text goes through `truncate`. Larger files are never handed over
/// whole — a head and a tail window are numbered and joined by the same
/// truncation marker, with the tail's line numbers taken from a streaming
/// count. Files above [`READ_LIMIT`] are refused rather than read.
pub(crate) fn read_numbered(path: &Path) -> Result<String, ReadError> {
    let len = std::fs::metadata(path)?.len();
    if len > READ_LIMIT {
        return Err(ReadError::TooLarge { len });
    }

    if len <= READ_ALL_MAX {
        let content = std::fs::read_to_string(path)?;
        let numbered = number_lines(&content, 1);
        return Ok(crate::context::truncate::truncate(&numbered, 30_000).into_owned());
    }

    // `len > READ_ALL_MAX` (64 KiB) so the two windows never overlap.
    let head_raw = read_range(path, 0, HEAD_BYTES as u64)?;
    let tail_start = len - TAIL_BYTES as u64;
    let tail_raw = read_range(path, tail_start, TAIL_BYTES as u64)?;
    // Line numbers for the tail need every line before it, so count them
    // without keeping them: `len` bytes of the file, 64 KiB at a time.
    let lines_before_tail = count_newlines(path, tail_start)?;

    // The head ends mid-line; number what is there, then cut the numbered text
    // back to the window so the result stays small.
    let head = first_bytes(&number_lines(&lossy_head(&head_raw), 1), HEAD_BYTES);

    // The tail usually starts mid-line. Drop that fragment first, unless the
    // window happens to begin on a line start.
    let tail_body = lossy_tail(&tail_raw);
    let starts_mid_line = !ends_with_newline(path, tail_start)?;
    let tail_body = match tail_body.find('\n') {
        Some(at) if starts_mid_line => tail_body[at + 1..].to_string(),
        _ => tail_body,
    };
    let tail = last_bytes(&number_lines(&tail_body, lines_before_tail + 1), TAIL_BYTES);

    // Bytes of the file that were neither counted nor shown.
    let shown = head_raw.len() as u64 + tail_body.len() as u64;
    let cut = len.saturating_sub(shown);

    Ok(format!("{head}\n{}\n{tail}", truncation_marker(cut, len)))
}

/// Read at most `max` bytes starting at `start`.
fn read_range(path: &Path, start: u64, max: u64) -> io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.take(max).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Count the `\n` bytes in the first `limit` bytes of `path`.
fn count_newlines(path: &Path, limit: u64) -> io::Result<u64> {
    let mut reader = std::fs::File::open(path)?.take(limit);
    let mut chunk = [0u8; CHUNK];
    let mut count = 0;
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(count);
        }
        count += chunk[..read].iter().filter(|byte| **byte == b'\n').count() as u64;
    }
}

/// Whether the byte just before `offset` is a newline, i.e. whether `offset`
/// is a line start.
fn ends_with_newline(path: &Path, offset: u64) -> io::Result<bool> {
    if offset == 0 {
        return Ok(true);
    }
    Ok(read_range(path, offset - 1, 1)?.first() == Some(&b'\n'))
}

/// Number `text` line by line, starting at `first`.
fn number_lines(text: &str, first: u64) -> String {
    text.lines()
        .enumerate()
        .map(|(index, line)| format!("{}: {}", first + index as u64, line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The first `max` bytes of `s`, cut at a UTF-8 char boundary.
fn first_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// The last `max` bytes of `s`, cut at a UTF-8 char boundary.
fn last_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    s[start..].to_string()
}

/// Decode a window that was cut mid-character at the end, without inventing a
/// replacement character for the cut itself.
fn lossy_head(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        // Stop at the incomplete or invalid sequence rather than pad it.
        Err(err) => String::from_utf8_lossy(&bytes[..err.valid_up_to()]).into_owned(),
    }
}

/// Decode a window that was cut mid-character at the start: the leading
/// continuation bytes belong to a character that is not in the window.
fn lossy_tail(bytes: &[u8]) -> String {
    let start = bytes
        .iter()
        .position(|byte| byte & 0xC0 != 0x80)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// A bounded capture of one output stream: the first [`HEAD_BYTES`], a rolling
/// window of the last [`TAIL_BYTES`], and the total number of bytes seen.
pub(crate) struct StreamCapture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: u64,
    limit: u64,
    limited: bool,
}

impl StreamCapture {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            head: Vec::new(),
            tail: VecDeque::new(),
            total: 0,
            limit,
            limited: false,
        }
    }

    /// Append a chunk of the stream. Returns `false` once the stream has passed
    /// its limit: the caller stops reading and kills the command.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> bool {
        self.total += chunk.len() as u64;

        let head_room = HEAD_BYTES.saturating_sub(self.head.len());
        let taken = head_room.min(chunk.len());
        self.head.extend_from_slice(&chunk[..taken]);
        for &byte in &chunk[taken..] {
            if self.tail.len() == TAIL_BYTES {
                self.tail.pop_front();
            }
            self.tail.push_back(byte);
        }

        if self.total > self.limit {
            self.limited = true;
        }
        !self.limited
    }

    /// Whether the capture stopped because the stream passed its limit.
    pub(crate) fn limited(&self) -> bool {
        self.limited
    }

    /// The captured text: the whole stream when it fit in the two windows,
    /// otherwise a head, the truncation marker and a tail.
    pub(crate) fn into_text(self) -> String {
        let head_bytes = self.head.len() as u64;
        let tail_bytes = self.tail.len() as u64;

        // Below both windows the head and the tail together are the stream.
        if self.total <= (HEAD_BYTES + TAIL_BYTES) as u64 {
            let mut bytes = self.head;
            bytes.extend(self.tail);
            return String::from_utf8_lossy(&bytes).into_owned();
        }

        let head = lossy_head(&self.head);
        let tail: Vec<u8> = self.tail.into_iter().collect();
        let tail = lossy_tail(&tail);
        let cut = self.total - head_bytes - tail_bytes;
        format!("{head}\n{}\n{tail}", truncation_marker(cut, self.total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_stream_is_returned_whole() {
        let mut capture = StreamCapture::new(STREAM_LIMIT);
        capture.push(b"hello ");
        capture.push(b"world");

        assert!(!capture.limited());
        assert_eq!(capture.into_text(), "hello world");
    }

    #[test]
    fn long_stream_keeps_head_and_tail_and_states_the_cut() {
        let mut capture = StreamCapture::new(STREAM_LIMIT);
        capture.push(&vec![b'a'; 60_000]);

        assert!(!capture.limited());
        let text = capture.into_text();
        assert!(text.starts_with(&"a".repeat(HEAD_BYTES)));
        assert!(text.ends_with(&"a".repeat(TAIL_BYTES)));
        assert!(text.contains("[... truncated 36000 of 60000 bytes ...]"));
    }

    #[test]
    fn stream_past_the_limit_is_flagged_and_stopped() {
        let mut capture = StreamCapture::new(1024);
        assert!(capture.push(&vec![b'x'; 1024]));
        assert!(!capture.push(&vec![b'y'; 40_000]));

        assert!(capture.limited());
        let text = capture.into_text();
        // The whole stream is counted, but only the windows are kept.
        assert!(text.contains("[... truncated 17024 of 41024 bytes ...]"));
        assert!(text.len() < 4 * HEAD_BYTES);
    }

    #[test]
    fn read_windows_a_large_file_with_real_line_numbers() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("big.txt");
        // 40,000 two-byte lines: 80,000 bytes, over READ_ALL_MAX.
        let body: String = (0..40_000).map(|_| "a\n").collect();
        std::fs::write(&path, &body).unwrap();

        let text = read_numbered(&path).unwrap();

        assert!(text.starts_with("1: a"), "head is numbered: {text:.80}");
        assert!(
            text.trim_end().ends_with("40000: a"),
            "tail keeps the real line number: {text:.80}"
        );
        assert!(text.contains("[... truncated "), "the cut is marked");
        assert!(
            text.len() < 4 * HEAD_BYTES,
            "bounded output, got {} bytes",
            text.len()
        );
    }

    #[test]
    fn read_refuses_files_over_the_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("huge.bin");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(READ_LIMIT + 1)
            .unwrap();

        let err = read_numbered(&path).unwrap_err();

        assert!(matches!(err, ReadError::TooLarge { .. }), "{err:?}");
        assert!(err.to_string().contains("read limit"), "{err}");
    }
}
