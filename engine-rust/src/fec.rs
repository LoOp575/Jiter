//! Formula #3: Bitwise XOR Parity FEC over Galois Field GF(2) with Interleaved Stride.

use std::collections::{HashMap, VecDeque};

pub const FEC_HEADER_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecFrame {
    pub group_id: u32,
    pub slot_index: u8,
    pub block_k: u8,
    pub is_parity: bool,
    pub payload: Vec<u8>,
}

impl FecFrame {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut out = Vec::with_capacity(FEC_HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.group_id.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.push(self.slot_index);
        let flags = (if self.is_parity { 0x80 } else { 0x00 }) | (self.block_k & 0x0F);
        out.push(flags);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn from_wire_bytes(wire: &[u8]) -> Option<Self> {
        if wire.len() < FEC_HEADER_SIZE {
            return None;
        }
        let group_id = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
        let payload_len = u16::from_be_bytes([wire[4], wire[5]]) as usize;
        if wire.len() < FEC_HEADER_SIZE + payload_len {
            return None;
        }
        let slot_index = wire[6];
        let flags_and_k = wire[7];
        let is_parity = (flags_and_k & 0x80) != 0;
        let block_k = flags_and_k & 0x0F;
        if !(1..=15).contains(&block_k) {
            return None;
        }
        Some(Self {
            group_id,
            slot_index,
            block_k,
            is_parity,
            payload: wire[FEC_HEADER_SIZE..FEC_HEADER_SIZE + payload_len].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPacket {
    pub group_id: u32,
    pub slot_index: u8,
    pub payload: Vec<u8>,
    pub was_recovered_by_parity: bool,
}

fn xor_buffers<'a, I>(bufs: I) -> Vec<u8>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let items: Vec<&[u8]> = bufs.into_iter().collect();
    let max_len = items.iter().map(|b| b.len()).max().unwrap_or(0);
    let mut acc = vec![0u8; max_len];
    for buf in items {
        for (dst, &src) in acc.iter_mut().zip(buf.iter()) {
            *dst ^= src;
        }
    }
    acc
}

fn pack_len_prefixed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn unpack_len_prefixed(framed: &[u8]) -> Option<Vec<u8>> {
    if framed.len() < 2 {
        return None;
    }
    let orig_len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    if orig_len > framed.len() - 2 {
        return None;
    }
    Some(framed[2..2 + orig_len].to_vec())
}

pub struct InterleavedXorFecEncoder {
    block_k: u8,
    stride: usize,
    next_group_id: u32,
    active_group_ids: Vec<u32>,
    group_slots: Vec<Vec<Vec<u8>>>,
    cursor: usize,
}

impl InterleavedXorFecEncoder {
    pub fn new(block_k: u8, stride: usize) -> Self {
        assert!((1..=15).contains(&block_k), "block_k must be in 1..=15");
        assert!((1..=16).contains(&stride), "stride must be in 1..=16");
        let mut active_group_ids = Vec::with_capacity(stride);
        for i in 0..stride {
            active_group_ids.push(i as u32);
        }
        Self {
            block_k,
            stride,
            next_group_id: stride as u32,
            active_group_ids,
            group_slots: (0..stride).map(|_| Vec::with_capacity(block_k as usize)).collect(),
            cursor: 0,
        }
    }

    fn alloc_group_id(&mut self) -> u32 {
        let gid = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);
        gid
    }

    pub fn encode_packet(&mut self, payload: &[u8]) -> Vec<FecFrame> {
        let lane = self.cursor;
        self.cursor = (self.cursor + 1) % self.stride;

        let gid = self.active_group_ids[lane];
        let slot_idx = self.group_slots[lane].len() as u8;

        let data_frame = FecFrame {
            group_id: gid,
            slot_index: slot_idx,
            block_k: self.block_k,
            is_parity: false,
            payload: payload.to_vec(),
        };

        self.group_slots[lane].push(pack_len_prefixed(payload));

        if self.group_slots[lane].len() < self.block_k as usize {
            return vec![data_frame];
        }

        let parity_payload = xor_buffers(self.group_slots[lane].iter().map(|v| v.as_slice()));
        let parity_frame = FecFrame {
            group_id: gid,
            slot_index: self.block_k,
            block_k: self.block_k,
            is_parity: true,
            payload: parity_payload,
        };

        self.group_slots[lane].clear();
        self.active_group_ids[lane] = self.alloc_group_id();
        vec![data_frame, parity_frame]
    }
}

struct GroupState {
    block_k: u8,
    data_slots: HashMap<u8, Vec<u8>>,
    parity_payload: Option<Vec<u8>>,
    done: bool,
}

pub struct InterleavedXorFecDecoder {
    max_tracked_groups: usize,
    order: VecDeque<u32>,
    groups: HashMap<u32, GroupState>,
    recovered_count: u64,
    unrecoverable_groups: u64,
}

impl InterleavedXorFecDecoder {
    pub fn new(max_tracked_groups: usize) -> Self {
        Self {
            max_tracked_groups: max_tracked_groups.max(1),
            order: VecDeque::new(),
            groups: HashMap::new(),
            recovered_count: 0,
            unrecoverable_groups: 0,
        }
    }

    pub fn recovered_count(&self) -> u64 {
        self.recovered_count
    }

    pub fn unrecoverable_groups(&self) -> u64 {
        self.unrecoverable_groups
    }

    fn evict_if_needed(&mut self) {
        while self.groups.len() > self.max_tracked_groups {
            if let Some(oldest_gid) = self.order.pop_front() {
                if let Some(evicted) = self.groups.remove(&oldest_gid) {
                    if evicted.data_slots.len() < evicted.block_k as usize {
                        self.unrecoverable_groups += 1;
                    }
                }
            } else {
                break;
            }
        }
    }

    pub fn receive(&mut self, frame: &FecFrame) -> Vec<RecoveredPacket> {
        let gid = frame.group_id;
        if !self.groups.contains_key(&gid) {
            self.order.push_back(gid);
            self.groups.insert(
                gid,
                GroupState {
                    block_k: frame.block_k,
                    data_slots: HashMap::new(),
                    parity_payload: None,
                    done: false,
                },
            );
            self.evict_if_needed();
        }

        let mut delivered = Vec::with_capacity(2);
        let mut recovered_now = false;

        if let Some(grp) = self.groups.get_mut(&gid) {
            if grp.done {
                return delivered;
            }

            if !frame.is_parity {
                if frame.slot_index < grp.block_k && !grp.data_slots.contains_key(&frame.slot_index) {
                    grp.data_slots
                        .insert(frame.slot_index, pack_len_prefixed(&frame.payload));
                    delivered.push(RecoveredPacket {
                        group_id: gid,
                        slot_index: frame.slot_index,
                        payload: frame.payload.clone(),
                        was_recovered_by_parity: false,
                    });
                }
            } else {
                grp.parity_payload = Some(frame.payload.clone());
            }

            if grp.data_slots.len() == grp.block_k as usize {
                grp.done = true;
                return delivered;
            }

            if let Some(ref parity) = grp.parity_payload {
                if grp.data_slots.len() + 1 == grp.block_k as usize {
                    if let Some(missing_idx) = (0..grp.block_k).find(|i| !grp.data_slots.contains_key(i)) {
                        let recovered_framed = xor_buffers(
                            grp.data_slots
                                .values()
                                .map(|v| v.as_slice())
                                .chain(std::iter::once(parity.as_slice())),
                        );
                        if let Some(recovered_payload) = unpack_len_prefixed(&recovered_framed) {
                            grp.data_slots.insert(missing_idx, recovered_framed);
                            grp.done = true;
                            recovered_now = true;
                            delivered.push(RecoveredPacket {
                                group_id: gid,
                                slot_index: missing_idx,
                                payload: recovered_payload,
                                was_recovered_by_parity: true,
                            });
                        }
                    }
                }
            }
        }

        if recovered_now {
            self.recovered_count += 1;
        }
        delivered
    }
}
