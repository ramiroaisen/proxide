use std::{
  hash::{DefaultHasher, Hash, Hasher},
  sync::atomic::{AtomicUsize, Ordering},
  net::IpAddr
};  

use crate::config::{Balance, HttpUpstream, StreamUpstream};

pub trait BalanceTarget {
  fn is_active(&self) -> bool;
  fn open_connections(&self) -> usize;
}

#[inline(always)]
pub fn balance_sort<'a, U: BalanceTarget>(upstreams: &'a [U], balance: Balance, remote_addr: IpAddr, round_robin_index: &AtomicUsize) -> Vec<&'a U> {
  match upstreams.len() {
    0 => vec![],
    1 => vec![&upstreams[0]],
    _ => {
      
      let mut sorted = match balance {
        Balance::RoundRobin => {
          let n = round_robin_index.fetch_add(1, Ordering::AcqRel) % upstreams.len();
          upstreams[n..].iter().chain(upstreams[0..n].iter()).collect::<Vec<_>>()
        }

        Balance::Random => {
          use rand::prelude::SliceRandom;
          let mut vec = upstreams.iter().collect::<Vec<_>>();
          vec.shuffle(&mut rand::thread_rng());
          vec
        }

        Balance::IpHash => {
          let mut hasher = DefaultHasher::new();
          remote_addr.hash(&mut hasher);
          let ip_hash = hasher.finish();
          
          let n = (ip_hash % upstreams.len() as u64) as usize;
          upstreams[n..].iter().chain(upstreams[0..n].iter()).collect::<Vec<_>>()
        }

        Balance::LeastConnections => {
          let mut with_count = upstreams.iter()
            .map(|upstream| {
              let conns = upstream.open_connections();
              (upstream, conns)
            })
            .collect::<Vec<_>>();

          with_count.sort_by(|(_, n1), (_, n2)| n1.cmp(n2));
          
          with_count
            .into_iter()
            .map(|(upstream, _)| upstream)
            .collect::<Vec<_>>()
        }
      };

      // is active false goes last (reverse from default)
      sorted.sort_by_key(|item| std::cmp::Reverse(item.is_active()));

      sorted
    }
  }
}

impl BalanceTarget for HttpUpstream {
  fn is_active(&self) -> bool {
    self.state_health.load(std::sync::atomic::Ordering::Relaxed)
  }

  fn open_connections(&self) -> usize {
    self.state_open_connections.load(std::sync::atomic::Ordering::Relaxed)
  }
}

impl BalanceTarget for StreamUpstream {
  fn is_active(&self) -> bool {
    true
  }

  fn open_connections(&self) -> usize {
    self.state_open_connections.load(std::sync::atomic::Ordering::Relaxed)
  }
}