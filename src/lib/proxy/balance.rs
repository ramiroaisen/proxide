use std::{
  net::IpAddr,
  num::NonZeroU32,
  sync::atomic::{AtomicUsize, Ordering},
};

use itertools::Itertools;
use nonzero::nonzero;

use crate::{
  config::{Balance, HttpUpstream, StreamUpstream},
  ketama::Ketama,
};

pub trait BalanceTarget {
  fn is_active(&self) -> bool;
  fn open_connections(&self) -> usize;
  fn weight(&self) -> NonZeroU32;
}

#[inline(always)]
pub fn balance_sort<'a, U: BalanceTarget>(
  upstreams: &'a [U],
  balance: Balance,
  ketama: Option<&Ketama>,
  remote_addr: IpAddr,
  round_robin_index: &AtomicUsize,
) -> Vec<&'a U> {
  match upstreams.len() {
    0 => vec![],
    1 => vec![&upstreams[0]],
    _ => {
      let mut sorted = match balance {
        Balance::RoundRobin => {
          let n = round_robin_index.fetch_add(1, Ordering::AcqRel) % upstreams.len();
          upstreams[n..]
            .iter()
            .chain(upstreams[0..n].iter())
            .collect::<Vec<_>>()
        }

        Balance::Random => {
          // we calculate the greatest common divisor of the weights to avoid extra allocations
          let divisor = {
            let mut divisor = nonzero!(1u32);
            for up in upstreams {
              divisor = gcd::euclid_nonzero_u32(divisor, up.weight());
            }
            divisor
          };

          use rand::prelude::SliceRandom;
          let mut vec = upstreams
            .iter()
            .enumerate()
            .flat_map(|(i, up)| {
              std::iter::repeat(i).take(up.weight().get() as usize / divisor.get() as usize)
            })
            .collect::<Vec<_>>();

          vec.shuffle(&mut rand::thread_rng());

          vec
            .into_iter()
            .dedup()
            .filter_map(|i| upstreams.get(i))
            .collect::<Vec<_>>()
        }

        Balance::IpHash => {
          let ketama = ketama
            .as_ref()
            .expect("ip-hash balance called without initializing internal ketama ring");

          let iter = match remote_addr {
            IpAddr::V4(addr) => ketama.list_for_key(&addr.octets()),
            IpAddr::V6(addr) => ketama.list_for_key(&addr.octets()),
          };

          iter
            .filter_map(|idx| upstreams.get(idx))
            .collect::<Vec<_>>()

          // let mut hasher = DefaultHasher::new();
          // remote_addr.hash(&mut hasher);
          // let ip_hash = hasher.finish();

          // let n = (ip_hash % upstreams.len() as u64) as usize;
          // upstreams[n..]
          //   .iter()
          //   .chain(upstreams[0..n].iter())
          //   .collect::<Vec<_>>()
        }

        Balance::LeastConnections => {
          let mut with_count = upstreams
            .iter()
            .map(|upstream| {
              let conns = upstream.open_connections();
              let weight = upstream.weight();
              let weighted = conns as f64 / weight.get() as f64;
              // we also take in account the weight absolute number
              // two weighted numbers would be equal to 0 with 0 connections but different weights
              (upstream, weighted, weight)
            })
            .collect::<Vec<_>>();

          with_count.sort_by(|(_, weighted1, weight1), (_, weighted2, weight2)| {
            match weighted1.partial_cmp(weighted2) {
              None | Some(std::cmp::Ordering::Equal) => weight2.cmp(weight1),
              Some(other) => other,
            }
          });

          with_count
            .into_iter()
            .map(|(upstream, _, _)| upstream)
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
    self
      .state_open_connections
      .load(std::sync::atomic::Ordering::Relaxed)
  }

  fn weight(&self) -> NonZeroU32 {
    self.weight.unwrap_or(nonzero!(1u32))
  }
}

impl BalanceTarget for StreamUpstream {
  fn is_active(&self) -> bool {
    true
  }

  fn open_connections(&self) -> usize {
    self
      .state_open_connections
      .load(std::sync::atomic::Ordering::Relaxed)
  }

  fn weight(&self) -> NonZeroU32 {
    self.weight.unwrap_or(nonzero!(1u32))
  }
}
