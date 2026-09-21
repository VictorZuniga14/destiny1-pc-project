//! MockByteSource unit tests.

use destiny1_network::byte_source::{ByteSource, ByteSourceError, MockByteSource};

#[test]
fn empty_source_returns_none() {
    let mut s = MockByteSource::new(Vec::<Vec<u8>>::new());
    assert_eq!(s.read().unwrap(), None);
    assert_eq!(s.read().unwrap(), None);
}

#[test]
fn single_chunk() {
    let mut s = MockByteSource::new(vec![vec![1, 2, 3]]);
    assert_eq!(s.read().unwrap(), Some(vec![1, 2, 3]));
    assert_eq!(s.read().unwrap(), None);
}

#[test]
fn multiple_chunks_preserve_order() {
    let mut s = MockByteSource::new(vec![vec![1], vec![2, 2], vec![3, 3, 3]]);
    assert_eq!(s.read().unwrap(), Some(vec![1]));
    assert_eq!(s.read().unwrap(), Some(vec![2, 2]));
    assert_eq!(s.read().unwrap(), Some(vec![3, 3, 3]));
    assert_eq!(s.read().unwrap(), None);
}

#[test]
fn eof_after_all_chunks() {
    let mut s = MockByteSource::new(vec![b"a".to_vec(), b"b".to_vec()]);
    assert!(s.read().unwrap().is_some());
    assert!(s.read().unwrap().is_some());
    assert_eq!(s.read().unwrap(), None);
    assert_eq!(s.remaining(), 0);
}

#[test]
fn mock_is_deterministic() {
    let chunks = vec![vec![9, 8], vec![7], vec![6, 5, 4]];
    let mut a = MockByteSource::new(chunks.clone());
    let mut b = MockByteSource::new(chunks);
    loop {
        let ra = a.read().unwrap();
        let rb = b.read().unwrap();
        assert_eq!(ra, rb);
        if ra.is_none() {
            break;
        }
    }
}

#[test]
fn intentional_error_is_not_eof() {
    let mut s = MockByteSource::from_results(vec![
        Ok(vec![1, 2]),
        Err(ByteSourceError::Failed("boom".into())),
        Ok(vec![3]),
    ]);
    assert_eq!(s.read().unwrap(), Some(vec![1, 2]));
    let err = s.read().unwrap_err();
    assert_eq!(err, ByteSourceError::Failed("boom".into()));
    // Error does not consume the remaining successful chunk.
    assert_eq!(s.read().unwrap(), Some(vec![3]));
    assert_eq!(s.read().unwrap(), None);
}
