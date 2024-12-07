use std::{
  net::IpAddr,
  num::NonZeroU32,
  sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
  config::{Balance, HttpUpstream, StreamUpstream},
  ketama::Ketama,
};
use itertools::Itertools;
use nonzero::nonzero;

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
      match balance {
        Balance::RoundRobin => {
          let mut active = vec![];
          let mut inactive = vec![];

          for up in upstreams {
            if up.is_active() {
              active.push(up);
            } else {
              inactive.push(up);
            }
          }

          let divisor = {
            let mut divisor = nonzero!(1u32);
            for up in &active {
              divisor = gcd::euclid_nonzero_u32(divisor, up.weight());
            }
            divisor
          };

          let round = {
            let mut round = 0;
            for up in &active {
              round += up.weight().get() / divisor.get();
            }
            round
          };

          let rest = round_robin_index.fetch_add(1, Ordering::AcqRel) % round as usize;

          let mut active_with_counter = active.into_iter().map(|up| (up, 0u32)).collect::<Vec<_>>();

          for _ in 0..rest {
            let min_idx =
              active_with_counter
                .iter()
                .position_min_by(|(up_a, recv_a), (up_b, recv_b)| {
                  let div_a = *recv_a as f64 / up_a.weight().get() as f64;
                  let div_b = *recv_b as f64 / up_b.weight().get() as f64;
                  match div_a.partial_cmp(&div_b) {
                    None | Some(std::cmp::Ordering::Equal) => up_b.weight().cmp(&up_a.weight()),
                    Some(other) => other,
                  }
                });

            if let Some(idx) = min_idx {
              active_with_counter[idx].1 += 1;
            }
          }

          inactive.sort_by_key(|up| std::cmp::Reverse(up.weight()));

          active_with_counter
            .into_iter()
            .map(|(up, recv)| {
              let weight = up.weight();
              let weighted_recv = recv as f64 / weight.get() as f64;
              (up, weighted_recv, weight)
            })
            .sorted_by(
              |(_, a_weighted_recv, a_weight), (_, b_weighted_recv, b_weight)| match a_weighted_recv
                .partial_cmp(b_weighted_recv)
              {
                None | Some(std::cmp::Ordering::Equal) => b_weight.cmp(a_weight),
                Some(other) => other,
              },
            )
            .map(|(up, _, _)| up)
            .chain(inactive)
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
              std::iter::repeat(i).take((up.weight().get() / divisor.get()) as usize)
            })
            .collect::<Vec<_>>();

          vec.shuffle(&mut rand::thread_rng());

          vec
            .into_iter()
            .dedup()
            .filter_map(|i| upstreams.get(i))
            .sorted_by(|a, b| b.is_active().cmp(&a.is_active()))
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
            .sorted_by(|a, b| b.is_active().cmp(&a.is_active()))
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
          upstreams
            .iter()
            .map(|upstream| {
              let conns = upstream.open_connections();
              let weight = upstream.weight();
              let weighted = conns as f64 / weight.get() as f64;
              // we also take in account the weight absolute number
              // two weighted numbers would be equal to 0 with 0 connections but different weights
              (upstream, weighted, weight)
            })
            .sorted_by(|(a, weighted1, weight1), (b, weighted2, weight2)| {
              match b.is_active().cmp(&a.is_active()) {
                std::cmp::Ordering::Equal => match weighted1.partial_cmp(weighted2) {
                  None | Some(std::cmp::Ordering::Equal) => weight2.cmp(weight1),
                  Some(other) => other,
                },
                other => other,
              }
            })
            .map(|(up, _, _)| up)
            .collect::<Vec<_>>()
        }
      }
    }
  }
}

impl BalanceTarget for HttpUpstream {
  fn is_active(&self) -> bool {
    self.state_health.load(std::sync::atomic::Ordering::Acquire)
  }

  fn open_connections(&self) -> usize {
    self
      .state_open_connections
      .load(std::sync::atomic::Ordering::Acquire)
  }

  fn weight(&self) -> NonZeroU32 {
    self.weight.unwrap_or(nonzero!(1u32))
  }
}

impl BalanceTarget for StreamUpstream {
  fn is_active(&self) -> bool {
    self.state_health.load(std::sync::atomic::Ordering::Acquire)
  }

  fn open_connections(&self) -> usize {
    self
      .state_open_connections
      .load(std::sync::atomic::Ordering::Acquire)
  }

  fn weight(&self) -> NonZeroU32 {
    self.weight.unwrap_or(nonzero!(1u32))
  }
}
