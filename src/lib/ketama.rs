use itertools::Itertools;
use std::{hash::Hasher, num::NonZeroU32};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ketama {
  // always sorted by hash
  // (Hash, Index)
  ring: Box<[(u32, usize)]>,
}

pub struct Bucket<Key: AsRef<[u8]>> {
  pub key: Key,
  pub node: usize,
  pub weight: NonZeroU32,
}

impl Ketama {
  fn idx(&self, key: &[u8]) -> Option<usize> {
    let key_hash = crc32fast::hash(key);
    if self.ring.is_empty() {
      return None;
    }

    for (i, (hash, _)) in self.ring.iter().enumerate() {
      if key_hash <= *hash {
        return Some(i);
      }
    }

    Some(0)
  }

  pub fn from_buckets<K: AsRef<[u8]>, I: Iterator<Item = Bucket<K>>>(iter: I) -> Self {
    let mut ring = Vec::new();
    // constant taken from pingora-ketama, pingora-ketama took it from nginx
    // this multiplies by the weight factor: Eg: weight=1 will create 160 nodes, weight=2 will create 320 nodes, etc
    let multiplier = 160;

    for bucket in iter {
      for i in 0..(bucket.weight.get() * multiplier) {
        let mut hasher = crc32fast::Hasher::new();
        for byte in bucket.key.as_ref() {
          hasher.write_u8(*byte);
        }
        hasher.write_u32(i);
        let hash = hasher.finalize();

        ring.push((hash, bucket.node));
      }
    }

    ring = ring.into_iter().dedup_by(|a, b| a.0 == b.0).collect();

    ring.sort_by(|a, b| a.0.cmp(&b.0));

    Self {
      ring: ring.into_boxed_slice(),
    }
  }

  pub fn list_for_key<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = usize> + Send + Sync + 'a {
    let start = match self.idx(key) {
      Some(start) => start,
      None => return KetamaNodeIter::Empty,
    };

    let iter = self
      .ring
      .iter()
      .skip(start)
      .chain(self.ring.iter().take(start))
      .map(|(_, idx)| *idx)
      .dedup();

    KetamaNodeIter::Pass(iter)
  }
}

pub enum KetamaNodeIter<T> {
  Empty,
  Pass(T),
}

impl<Item, I: Iterator<Item = Item>> Iterator for KetamaNodeIter<I> {
  type Item = Item;

  fn next(&mut self) -> Option<Self::Item> {
    match self {
      KetamaNodeIter::Empty => None,
      KetamaNodeIter::Pass(iter) => iter.next(),
    }
  }
}
