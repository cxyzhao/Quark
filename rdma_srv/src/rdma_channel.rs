// Copyright (c) 2021 Quark Container Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::sync::Arc;
use alloc::sync::Weak;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};
use std::mem;
use std::ops::{Deref, DerefMut};

use super::rdma_agent::*;
use super::rdma_conn::*;
use super::rdma_srv::*;

// RDMA Channel
use super::qlib::bytestream::*;
use super::qlib::common::*;
use super::qlib::linux_def::*;
use super::qlib::rdma_share::*;
use super::qlib::socket_buf::SocketBuff;
use super::qlib::kernel::*;

// AES-GCM for encrypt
pub static CurTSC: Tsc = Tsc::New();
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-256-GCM
use aes_gcm::aead::{Aead, NewAead};

// LPM for forwarding
use std::net::Ipv4Addr;
use std::str::FromStr;
use lazy_static::lazy_static;

// Define a structure for network prefixes
#[derive(Copy, Clone)]
pub struct NetworkPrefix {
    prefix: Ipv4Addr,
    mask: u32,
    destination: Ipv4Addr,
}

impl NetworkPrefix {
    // Constructor to create a new NetworkPrefix
    fn new(prefix: &str, mask: u32, destination: &str) -> Self {
        NetworkPrefix {
            prefix: Ipv4Addr::from_str(prefix).expect("Invalid IP address format"),
            mask: mask,
            destination: Ipv4Addr::from_str(destination).expect("Invalid IP address format"),
        }
    }

    // Check if a given IP address matches this network prefix
    fn matches(&self, addr: &Ipv4Addr) -> bool {
        let mask = !((1 << (32 - self.mask)) - 1);
        let prefix_int = u32::from(self.prefix) & mask;
        let addr_int = u32::from(*addr) & mask;
        prefix_int == addr_int
    }
}

// Populate 32 NetworkPrefix constants for testing
lazy_static! {
    pub static ref NETWORK_PREFIXES: Mutex<Vec<NetworkPrefix>> = Mutex::new(vec![
        NetworkPrefix::new("10.0.0.0", 24, "10.0.0.1"),
        NetworkPrefix::new("10.0.1.0", 24, "10.0.1.1"),
        NetworkPrefix::new("10.0.2.0", 24, "10.0.2.1"),
        NetworkPrefix::new("10.0.3.0", 24, "10.0.3.1"),
        NetworkPrefix::new("10.0.4.0", 24, "10.0.4.1"),
        NetworkPrefix::new("10.0.5.0", 24, "10.0.5.1"),
        NetworkPrefix::new("10.0.6.0", 24, "10.0.6.1"),
        NetworkPrefix::new("10.0.7.0", 24, "10.0.7.1"),
        NetworkPrefix::new("10.0.8.0", 24, "10.0.8.1"),
        NetworkPrefix::new("10.0.9.0", 24, "10.0.9.1"),
        NetworkPrefix::new("10.0.10.0", 24, "10.0.10.1"),
        NetworkPrefix::new("10.0.11.0", 24, "10.0.11.1"),
        NetworkPrefix::new("10.0.12.0", 24, "10.0.12.1"),
        NetworkPrefix::new("10.0.13.0", 24, "10.0.13.1"),
        NetworkPrefix::new("10.0.14.0", 24, "10.0.14.1"),
        NetworkPrefix::new("10.0.15.0", 24, "10.0.15.1"),
        NetworkPrefix::new("10.0.16.0", 24, "10.0.16.1"),
        NetworkPrefix::new("10.0.17.0", 24, "10.0.17.1"),
        NetworkPrefix::new("10.0.18.0", 24, "10.0.18.1"),
        NetworkPrefix::new("10.0.19.0", 24, "10.0.19.1"),
        NetworkPrefix::new("10.0.20.0", 24, "10.0.20.1"),
        NetworkPrefix::new("10.0.21.0", 24, "10.0.21.1"),
        NetworkPrefix::new("10.0.22.0", 24, "10.0.22.1"),
        NetworkPrefix::new("10.0.23.0", 24, "10.0.23.1"),
        NetworkPrefix::new("10.0.24.0", 24, "10.0.24.1"),
        NetworkPrefix::new("10.0.25.0", 24, "10.0.25.1"),
        NetworkPrefix::new("10.0.26.0", 24, "10.0.26.1"),
        NetworkPrefix::new("10.0.27.0", 24, "10.0.27.1"),
        NetworkPrefix::new("10.0.28.0", 24, "10.0.28.1"),
        NetworkPrefix::new("10.0.29.0", 24, "10.0.29.1"),
        NetworkPrefix::new("10.0.30.0", 24, "10.0.30.1"),
        NetworkPrefix::new("10.0.31.0", 24, "10.0.31.1")
    ]);
}

// VXLAN for encapsulation
const VXLAN_VNI: u32 = 12345;  // VXLAN Network Identifier
const VXLAN_UDP_PORT: u16 = 4789;  // Standard VXLAN UDP port
const SRC_IP: u32 = 0xC0A80001; // Source IP address (e.g., 192.168.0.1)
const DST_IP: u32 = 0xC0A80002; // Destination IP address (e.g., 192.168.0.2)
const SRC_MAC: [u8; 6] = [0x00, 0x0C, 0x29, 0x48, 0x57, 0x54]; // Source MAC address
const DST_MAC: [u8; 6] = [0x00, 0x0C, 0x29, 0x12, 0x34, 0x56]; // Destination MAC address

#[derive(Clone)]
pub struct EthernetFrame {
    // Assumed structure of an Ethernet frame
    data: [u8; 8192], 
}

pub struct VxlanPacket {
    // Structure of a VXLAN encapsulated packet
    ethernet_frame: EthernetFrame,
    // ... Other VXLAN-related fields
    // VXLAN-specific fields
    vni: u32,          // VXLAN Network Identifier
    src_ip: u32,       // Source IP address
    dst_ip: u32,       // Destination IP address
    src_mac: [u8; 6],  // Source MAC address
    dst_mac: [u8; 6],  // Destination MAC address
    vxlan_port: u16,   // VXLAN UDP port
}

impl VxlanPacket {
    // Convert the entire VxlanPacket to a byte vector
    fn to_byte_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Start with the ethernet frame data
        bytes.extend_from_slice(&self.ethernet_frame.data);

        // Add other VXLAN-specific fields as bytes
        bytes.extend_from_slice(&self.vni.to_be_bytes()); // VXLAN Network Identifier
        bytes.extend_from_slice(&self.src_ip.to_be_bytes()); // Source IP address
        bytes.extend_from_slice(&self.dst_ip.to_be_bytes()); // Destination IP address
        bytes.extend_from_slice(&self.src_mac); // Source MAC address
        bytes.extend_from_slice(&self.dst_mac); // Destination MAC address
        bytes.extend_from_slice(&self.vxlan_port.to_be_bytes()); // VXLAN UDP port

        bytes
    }
}

static ENCRYPT_CYCLE: AtomicU64 = AtomicU64::new(0);
static ENCRYPT_COUNT: AtomicU64 = AtomicU64::new(0);
static DECRYPT_CYCLE: AtomicU64 = AtomicU64::new(0);
static DECRYPT_COUNT: AtomicU64 = AtomicU64::new(0);
static LPM_SEND_CYCLE: AtomicU64 = AtomicU64::new(0);
static LPM_SEND_COUNT: AtomicU64 = AtomicU64::new(0);
static LPM_RECV_CYCLE: AtomicU64 = AtomicU64::new(0);
static LPM_RECV_COUNT: AtomicU64 = AtomicU64::new(0);
static VXLAN_ENCAPSULATE_CYCLE: AtomicU64 = AtomicU64::new(0);
static VXLAN_ENCAPSULATE_COUNT: AtomicU64 = AtomicU64::new(0);
static VXLAN_DECAPSULATE_CYCLE: AtomicU64 = AtomicU64::new(0);
static VXLAN_DECAPSULATE_COUNT: AtomicU64 = AtomicU64::new(0);

fn update_encrypt_data(added_cycle: u64) {
    let count = ENCRYPT_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    ENCRYPT_CYCLE.fetch_add(added_cycle, Ordering::SeqCst);

    if count % 1000 == 0 {
        let total_cycles = ENCRYPT_CYCLE.load(Ordering::SeqCst);
        println!("Encryption count: {}, Total cycles: {}", count, total_cycles);
    }
}

fn update_decrypt_data(added_cycle: u64) {
    let count = DECRYPT_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    DECRYPT_CYCLE.fetch_add(added_cycle, Ordering::SeqCst);

    if count % 1000 == 0 {
        let total_cycles = DECRYPT_CYCLE.load(Ordering::SeqCst);
        println!("Decryption count: {}, Total cycles: {}", count, total_cycles);
    }
}

fn update_lpm_data(added_cycle: u64, send: bool) {
    if send {
        let count = LPM_SEND_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
        LPM_SEND_CYCLE.fetch_add(added_cycle, Ordering::SeqCst);

        if count % 1000 == 0 {
            let total_cycles = LPM_SEND_CYCLE.load(Ordering::SeqCst);
            println!("LPM Send count: {}, Total cycles: {}", count, total_cycles);
        }
    }else{
        let count = LPM_RECV_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
        LPM_RECV_CYCLE.fetch_add(added_cycle, Ordering::SeqCst);

        if count % 1000 == 0 {
            let total_cycles = LPM_RECV_CYCLE.load(Ordering::SeqCst);
            println!("LPM Recv count: {}, Total cycles: {}", count, total_cycles);
        }

    }
}

fn update_vxlan_encapsulate_data(added_cycle: u64) {
    let count = VXLAN_ENCAPSULATE_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    VXLAN_ENCAPSULATE_CYCLE.fetch_add(added_cycle, Ordering::SeqCst);

    if count % 1000 == 0 {
        let total_cycles = VXLAN_ENCAPSULATE_CYCLE.load(Ordering::SeqCst);
        println!("VXLAN Encap count: {}, Total cycles: {}", count, total_cycles);
    }
}

fn update_vxlan_decapsulate_data(added_cycle: u64) {
    let count = VXLAN_DECAPSULATE_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    VXLAN_DECAPSULATE_CYCLE.fetch_add(added_cycle, Ordering::SeqCst);

    if count % 1000 == 0 {
        let total_cycles = VXLAN_DECAPSULATE_CYCLE.load(Ordering::SeqCst);
        println!("VXLAN decap count: {}, Total cycles: {}", count, total_cycles);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ChannelStatus {
    CLOSED = 0,
    LISTEN = 1,
    SYN_SENT = 2,
    SYN_RECEIVED = 3,
    ESTABLISHED = 4,
    CLOSE_WAIT = 5,
    FIN_WAIT_1 = 6,
    CLOSING = 7,
    LAST_ACK = 8,
    FIN_WAIT_2 = 9,
    TIME_WAIT = 10,
}

#[derive(Clone, Default, Debug)]
#[repr(C)]
pub struct ChannelRDMAInfo {
    pub remoteId: u32,
    pub raddr: u64,     /* Read Buffer address */
    pub rlen: u32,      /* Read Buffer len */
    pub rkey: u32,      /* Read Buffer Remote key */
    pub offset: u32,    //read buffer offset
    pub freespace: u32, //read buffer free space size
    pub sending: bool,  // the writeimmediately is ongoing
}

impl ChannelRDMAInfo {
    pub fn Size() -> usize {
        return mem::size_of::<Self>();
    }
}

pub struct RDMAChannelIntern {
    pub localId: u32,
    // pub remoteId: u32,
    // pub readBuf: Mutex<ByteStream>,
    // pub writeBuf: Mutex<ByteStream>,
    // pub consumeReadData: &'static AtomicU64,
    // pub sockfd: u32, //TODO: this is used to associate SQE and CQE, need double check it's a proper way to do it or not
    pub sockBuf: SocketBuff,
    pub lkey: u32,
    pub rkey: u32,
    pub raddr: u64,
    pub length: u32,
    pub writeCount: AtomicUsize, //when run the writeimm, save the write bytes count here
    pub remoteChannelRDMAInfo: Mutex<ChannelRDMAInfo>,

    // rdma connect to remote node
    pub conn: RDMAConn,

    // rdma agent connected to rdma client
    pub agent: RDMAAgent,

    pub vpcId: u32,
    pub srcIpAddr: u32,
    pub dstIpAddr: u32,
    pub srcPort: u16,
    pub dstPort: u16,
    pub status: Mutex<ChannelStatus>,
    pub duplexMode: Mutex<DuplexMode>,
    pub ioBufIndex: u32,
    pub closeRequestedByClient: Mutex<bool>,
    pub pendingShutdown: Mutex<bool>,
    pub finReceived: Mutex<bool>,
}

impl Drop for RDMAChannelIntern {
    fn drop(&mut self) {
        RDMA_SRV.channelIdMgr.lock().Remove(self.localId);
        self.agent.ioBufIdMgr.lock().Remove(self.ioBufIndex);
    }
}

impl RDMAChannelIntern {
    pub fn test(&self) {
        println!("testtest");
    }

    pub fn UpdateRemoteRDMAInfo(&self, remoteId: u32, raddr: u64, rlen: u32, rkey: u32) {
        *self.remoteChannelRDMAInfo.lock() = ChannelRDMAInfo {
            remoteId,
            raddr,
            rlen,
            rkey,
            offset: 0,
            freespace: rlen,
            sending: false,
        }
    }

    pub fn RDMAWriteImm(
        &self,
        localAddr: u64,
        remoteAddr: u64,
        writeCount: usize,
        rkey: u32,
        remoteId: u32,
        wrId: u64,
    ) -> Result<()> {
        // println!("RDMAChannelIntern::RDMAWriteImm 1, localAddr: {}, remoteAddr: {}, writeCount: {}, localId: {}, remoteId: {}, lkey: {}, rkey: {}", localAddr, remoteAddr, writeCount, self.localId, remoteId, self.lkey, rkey);
        self.conn.RDMAWriteImm(
            localAddr, remoteAddr, writeCount, wrId, remoteId, self.lkey, rkey,
        )?;

        self.writeCount.store(writeCount, QOrdering::RELEASE);
        return Ok(());
    }

    pub fn ProcessRDMAWriteImmFinish(&self, finSent: bool) {
        // println!("qq1: RDMAChannel::ProcessRDMAWriteImmFinish enter");
        // RDMA_SRV.timestamps.lock().push(CurTSC.Rdtsc());
        // let len = RDMA_SRV.timestamps.lock().len();
        // let mut i = 0;
        // let v1 = RDMA_SRV.timestamps.lock()[0];
        // // let mut v2 = RDMA_SRV.timestamps.lock()[1];
        // // println!("qq, Handle connect request time len: {}", len);
        // println!("{}", RDMA_SRV.timestamps.lock()[len - 1] - v1);
        // loop {
        //     println!("{}", RDMA_SRV.timestamps.lock()[i]);
        //     i += 1;
        //     if i == len {
        //         break;
        //     }
        //     // v1 = v2;
        //     // v2 = RDMA_SRV.timestamps.lock()[i];            
        // }
        // RDMA_SRV.timestamps.lock().clear();
        // println!("RDMAChannel::ProcessRDMAWriteImmFinish 1");
        let mut remoteInfo = self.remoteChannelRDMAInfo.lock();
        remoteInfo.sending = false;

        let writeCount = self.writeCount.load(QOrdering::ACQUIRE);
        // debug!("ProcessRDMAWriteImmFinish::1 writeCount: {}", writeCount);

        let (mut trigger, addr, availableDataLen) = self
            .sockBuf
            .ConsumeAndGetAvailableWriteBuf(writeCount as usize);

        if finSent {
            if matches!(*self.status.lock(), ChannelStatus::FIN_WAIT_1) {
                *self.status.lock() = ChannelStatus::FIN_WAIT_2;
                // TODO: notify client.
                // self.agent.SendResponse(RDMAResp {
                //     user_data: 0,
                //     msg: RDMARespMsg::RDMAFinNotify(RDMAFinNotifyResp {
                //         // sockfd: self.sockfd,
                //         channelId: self.localId,
                //         event: FIN_SENT_TO_PEER,
                //     }),
                // });
            } else if matches!(*self.status.lock(), ChannelStatus::LAST_ACK)
                && availableDataLen == 0
            {
                *self.status.lock() = ChannelStatus::CLOSED;
                if *self.closeRequestedByClient.lock() {
                    self.ReleaseChannelResource();
                }
            } else {
                // error!(
                //     "TODO: status: {:?} is not handled after finSent",
                //     *self.status.lock()
                // );
            }

            // return;
        }
        // println!(
        //         "ProcessRDMAWriteImmFinish::3, sockfd: {}, channelId: {}, len: {}, writeCount: {}, trigger: {}",
        //         self.sockfd, self.localId, _len, writeCount, trigger
        //     );
        #[cfg(offload = "yes")]{
            trigger = true;
        }
        if trigger {
            if self.localId != 0 {
                // println!("ProcessRDMAWriteImmFinish: before SendResponse");
                self.agent.SendResponse(RDMAResp {
                    user_data: 0,
                    msg: RDMARespMsg::RDMANotify(RDMANotifyResp {
                        // sockfd: self.sockfd,
                        channelId: self.localId,
                        event: EVENT_OUT,
                    }),
                });
            }
        }

        if availableDataLen == 0 && *self.pendingShutdown.lock() {
            self.agent.SendResponse(RDMAResp {
                user_data: 0,
                msg: RDMARespMsg::RDMANotify(RDMANotifyResp {
                    // sockfd: self.sockfd,
                    channelId: self.localId,
                    event: EVENT_PENDING_SHUTDOWN,
                }),
            });
            *self.pendingShutdown.lock() = false;
        }

        // println!(
        //     "RDMAChannel::ProcessRDMAWriteImmFinish 2, localId: {}",
        //     self.localId
        // );
        if self.localId != 0 {
            // if 2 * self.sockBuf.consumeReadData.load(Ordering::Acquire)
            //     > self.sockBuf.readBuf.lock().BufSize() as u64
            // if 2 * self.sockBuf.consumeReadData.load(Ordering::Relaxed) > 65536 as u64 {
            //     println!("Control Channel to send consumed data, channel id: {}", self.localId);
            //     self.SendConsumedDataInternal(remoteInfo.remoteId);
            // }
            // self.SendConsumedDataInternal(remoteInfo.remoteId);
        } else {
            // TODO: is it needed to send consumedData for control channel here, not now!
        }
        // println!("RDMAChannel::ProcessRDMAWriteImmFinish 3, addr: {}", addr);
        if addr != 0 || self.ShouldSendFIN() {
            // self.RDMASendLocked(remoteInfo)
            self.conn.RDMAWrite(self, remoteInfo);
        }
    }

    fn SendConsumedDataInternal(&self, remoteChannelId: u32) {
        let readCount = self.sockBuf.GetAndClearConsumeReadData();
        // println!("SendConsumedData 1, readCount: {}", readCount);
        if readCount > 0 {
            self.conn
                .ctrlChan
                .lock()
                .SendControlMsg(ControlMsgBody::ConsumedData(ConsumedData {
                    remoteChannelId: remoteChannelId,
                    consumedData: readCount as u32,
                    recvRequestCount: self
                        .conn
                        .localInsertedRecvRequestCount
                        .swap(0, Ordering::SeqCst),
                }));
        }
    }
    pub fn SendConsumedData(&self) {
        self.SendConsumedDataInternal(self.GetRemoteChannelId());
    }

    pub fn PendingShutdown(&self) {
        // error!("PendingShutdown, 1, channelId: {}", self.localId);
        if !self.sockBuf.HasWriteData() {// || *self.finReceived.lock() {
            // if *self.finReceived.lock() {
            //     let available = self.sockBuf.WriteBufAvailableDataSize();
            //     self.sockBuf.ConsumeWriteBuf(available);
            //     error!("PendingShutdown, available: {}, self.sockBuf.HasWriteData(): {}", available, self.sockBuf.HasWriteData());
            // }
            self.agent.SendResponse(RDMAResp {
                user_data: 0,
                msg: RDMARespMsg::RDMANotify(RDMANotifyResp {
                    channelId: self.localId,
                    event: EVENT_PENDING_SHUTDOWN,
                }),
            });
            // error!("PendingShutdown, 2, EVENT_PENDING_SHUTDOWN, channelId: {}", self.localId);
        }
        else {
            *self.pendingShutdown.lock() = true;
        }
    }

    pub fn Shutdown(&self) {
        self.HandleUserClose();
    }

    // handle both shutdown and close
    fn HandleUserClose(&self) {
        //TODO: should handle other status too.
        if matches!(*self.status.lock(), ChannelStatus::ESTABLISHED) {
            *self.status.lock() = ChannelStatus::FIN_WAIT_1;
            self.RDMASend();
        } else if matches!(*self.status.lock(), ChannelStatus::CLOSE_WAIT) {
            *self.status.lock() = ChannelStatus::LAST_ACK;
            self.RDMASend();
        } else {
            self.RDMASend();
        }
    }

    pub fn Close(&self) {
        if *self.closeRequestedByClient.lock() {
            return;
        }
        *self.closeRequestedByClient.lock() = true;
        let channelStatus = *self.status.lock();
        if matches!(channelStatus, ChannelStatus::TIME_WAIT)
            || matches!(channelStatus, ChannelStatus::CLOSED)
        {
            self.ReleaseChannelResource();
            return;
        }
        self.HandleUserClose();
    }

    fn GetRemoteChannelId(&self) -> u32 {
        self.remoteChannelRDMAInfo.lock().remoteId
    }

    fn decrypt_data(&self, addr: *const u8, len: usize, key: &[u8; 32], nonce: &[u8; 12]) -> Result<()>  {
        let before = CurTSC.Rdtsc() as u64;
    
        let aead = Aes256Gcm::new(Key::from_slice(key));
        let data = unsafe { std::slice::from_raw_parts(addr, len) };
    
        aead.decrypt(Nonce::from_slice(nonce), data.as_ref());
    
        let after = CurTSC.Rdtsc() as u64;
        update_decrypt_data(after - before);
    
        return Ok(());
    }

    fn calculate_ip_checksum(&self, header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..header.len()).step_by(2) {
            let word = (header[i] as u16) << 8 | (header[i + 1] as u16);
            sum = sum + word as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    fn calculate_udp_checksum(&self, pseudo_header: &[u8], udp_header: &[u8], data: &[u8]) -> u16 {
        let mut sum = 0u32;
    
        // Add pseudo-header sum
        for i in (0..pseudo_header.len()).step_by(2) {
            sum += ((pseudo_header[i] as u16) << 8 | pseudo_header[i + 1] as u16) as u32;
        }
    
        // Add UDP header and data sum
        let total_length = udp_header.len() + data.len();
        for i in 0..total_length {
            let word = if i < udp_header.len() {
                (udp_header[i] as u16) << 8 | (udp_header.get(i + 1).cloned().unwrap_or(0) as u16)
            } else {
                let data_index = i - udp_header.len();
                (data[data_index] as u16) << 8 | (data.get(data_index + 1).cloned().unwrap_or(0) as u16)
            };
            sum = sum + word as u32;
        }
    
        // Finalize checksum
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    fn vxlan_decapsulate(&self, addr: *const u8, len: usize) -> Result<EthernetFrame> {
        let before = CurTSC.Rdtsc() as u64;
    
        // Ensure we have a buffer large enough to hold a VxlanPacket
        let mut buffer: Vec<u8>;
        let vxlan_packet: &VxlanPacket;
        if len < std::mem::size_of::<VxlanPacket>() {
            // If the provided data is smaller than the size of VxlanPacket,
            // create a buffer and fill it with data, padding the rest with zeros
            buffer = vec![0; 1500];
            vxlan_packet = unsafe { &*(buffer.as_ptr() as *const VxlanPacket) };
        } else {
            // If the length is sufficient, just cast the pointer to a VxlanPacket
            vxlan_packet = unsafe { &*(addr as *const VxlanPacket) };
        }
    
        // Extract the Ethernet frame from the VXLAN packet
        let ethernet_frame = vxlan_packet.ethernet_frame.clone();

        let packet_data = vxlan_packet.to_byte_vec();

        // Extracting IP header
        let ip_header_start = 14; // Assuming Ethernet header is 14 bytes
        let ip_header_end = ip_header_start + 20; // Typically 20 bytes for IPv4 header
        let ip_header = &packet_data[ip_header_start..ip_header_end];
    
        // Extracting UDP header
        let udp_header_start = ip_header_end;
        let udp_header_end = udp_header_start + 8; // UDP header is 8 bytes long
        let udp_header = &packet_data[udp_header_start..udp_header_end];
    
        // Extracting UDP data
        let udp_data_start = udp_header_end;
        let udp_data_end = packet_data.len(); // Using the rest of the packet data
        let udp_data = &packet_data[udp_data_start..udp_data_end];
    
        // Constructing pseudo-header for UDP checksum calculation
        let mut pseudo_header = vec![];
        pseudo_header.extend_from_slice(&vxlan_packet.src_ip.to_be_bytes()); // Source IP address
        pseudo_header.extend_from_slice(&vxlan_packet.dst_ip.to_be_bytes()); // Destination IP address
        pseudo_header.push(0); // Zero byte, must be 0
        pseudo_header.push(17); // Protocol number for UDP is 17
        pseudo_header.extend_from_slice(&(udp_header.len() as u16 + udp_data.len() as u16).to_be_bytes());
    
        // Calculating UDP checksum
        self.calculate_udp_checksum(&pseudo_header, udp_header, udp_data);
    
        // Calculating IP checksum
        self.calculate_ip_checksum(ip_header);
    
        let after = CurTSC.Rdtsc() as u64;
        update_vxlan_decapsulate_data(after - before);
    
        Ok(ethernet_frame)
    }

    pub fn ProcessRDMARecvWriteImm(&self, qpNum: u32, recvCount: u64, finReceived: bool) {
        if finReceived {
            *self.finReceived.lock() = true;
        }
        let _res = self
            .conn
            .PostRecv(qpNum, self.localId as u64, self.raddr, self.rkey);

        if recvCount > 0 {
            // debug!("ProcessRDMARecvWriteImm::1, channelId: {}, recvCount: {}", self.localId, recvCount);
            let (mut trigger, _addr, _len) = self.sockBuf.ProduceAndGetFreeReadBuf(recvCount as usize);
            
            const KEY: [u8; 32] = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            ]; 
            const NONCE: [u8; 12] = [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x12, 0x34, 0x56, 0x78,
            ]; 
            let (addr_ptr, available) = self.sockBuf.GetReadDataAddr(); // Convert the u64 address to a pointer
            let addr_ptr = addr_ptr as *const u8;
            let len = recvCount as usize;
            let decrypted_data = self.decrypt_data(addr_ptr, len, &KEY, &NONCE)
            .expect("Decryption failed");

            let src_ip = "10.2.0.100";
            self.longest_prefix_match(src_ip, false);
            // match self.longest_prefix_match(src_ip) {
            //     Some(dst) => println!("Destination IP for {} is {}", src_ip, dst),
            //     None => println!("No match found for {}", src_ip),
            // }

            let eth_packet = self.vxlan_decapsulate(addr_ptr, len)
            .expect("Failed to encapsulate VXLAN packet");

            // debug!("ProcessRDMARecvWriteImm::2, trigger {}", trigger);
            // println!(
            //     "ProcessRDMARecvWriteImm::3, channelId: {}, len: {}, recvCount: {}, trigger: {}",
            //     // self.sockfd,
            //     self.localId,
            //     len,
            //     recvCount,
            //     trigger
            // );
            #[cfg(offload = "yes")]{
                trigger = true;
            }
            if trigger {
                // TODO: notify 'client' via CQ
                // println!("ProcessRDMARecvWriteImm: send EVENT_IN, recvCount: {}", recvCount);
                self.agent.SendResponse(RDMAResp {
                    user_data: 0,
                    msg: RDMARespMsg::RDMANotify(RDMANotifyResp {
                        // sockfd: self.sockfd,
                        channelId: self.localId,
                        event: EVENT_IN,
                    }),
                });
                // if self.localId == 1 {
                //     debug!("ProcessRDMARecvWriteImm sleep 2 sec");
                //     let ten_millis = std::time::Duration::from_millis(2000);
                //     std::thread::sleep(ten_millis);
                //     self.agent.SendResponse(RDMAResp {
                //         user_data: 0,
                //         msg: RDMARespMsg::RDMANotify(RDMANotifyResp {
                //             // sockfd: self.sockfd,
                //             channelId: self.localId,
                //             event: EVENT_IN,
                //         }),
                //     });
                // }
            } else {
                // println!("ProcessRDMARecvWriteImm 4, trigger: {}", trigger);
            }
        }

        if finReceived {
            if matches!(*self.status.lock(), ChannelStatus::ESTABLISHED) {
                *self.status.lock() = ChannelStatus::CLOSE_WAIT;
            } else if matches!(*self.status.lock(), ChannelStatus::FIN_WAIT_2) {
                *self.status.lock() = ChannelStatus::TIME_WAIT;
                if *self.closeRequestedByClient.lock() {
                    self.ReleaseChannelResource();
                }
            }

            // debug!("ProcessRDMARecvWriteImm 7");
            self.agent.SendResponse(RDMAResp {
                user_data: 0,
                msg: RDMARespMsg::RDMAFinNotify(RDMAFinNotifyResp {
                    channelId: self.localId,
                    event: FIN_RECEIVED_FROM_PEER,
                }),
            });
            // println!("ProcessRDMARecvWriteImm 7");
        }
    }

    fn ReleaseChannelResource(&self) {
        RDMA_SRV.channels.lock().remove(&self.localId);
    }

    pub fn ProcessRemoteConsumedData(&self, consumedCount: u32) {
        // println!("RDMAChannel::ProcessRemoteConsumedData 1");
        let trigger;
        {
            let mut remoteInfo = self.remoteChannelRDMAInfo.lock();
            trigger = remoteInfo.freespace == 0;
            remoteInfo.freespace += consumedCount as u32;
        }

        if trigger {
            self.RDMASend();
        }
    }

    pub fn RDMASend(&self) {
        // println!("qq1: RDMAChannel::RDMASend enter");
        // RDMA_SRV.timestamps.lock().push(CurTSC.Rdtsc());
        let remoteInfo = self.remoteChannelRDMAInfo.lock();
        if remoteInfo.sending == true {
            return; // the sending is ongoing
        }
        //self.RDMASendLockedNew(remoteInfo);
        self.conn.RDMAWrite(self, remoteInfo);
    }

    pub fn RDMASendFromConn(&self, remoteRecvRequestCount: &mut MutexGuard<u32>) {
        let remoteInfo = self.remoteChannelRDMAInfo.lock();
        self.RDMASendLocked(remoteInfo, remoteRecvRequestCount);
    }

    fn ShouldSendFIN(&self) -> bool {
        match *self.status.lock() {
            ChannelStatus::FIN_WAIT_1 => true,
            ChannelStatus::LAST_ACK => true,
            _ => false,
        }
    }

    fn encrypt_data(&self, addr: *const u8, len: usize, key: &[u8; 32], nonce: &[u8; 12]) -> Result<()>  {
        let before = CurTSC.Rdtsc() as u64;

        let aead = Aes256Gcm::new(Key::from_slice(key));
        let data = unsafe { std::slice::from_raw_parts(addr, len) };
    
        aead.encrypt(Nonce::from_slice(nonce), data.as_ref());

        let after = CurTSC.Rdtsc() as u64;
        update_encrypt_data(after - before);
        return Ok(());
    }

    fn longest_prefix_match(&self, src_ip: &str, send: bool) -> Option<String> {
        let before = CurTSC.Rdtsc() as u64;

        let src_addr = match Ipv4Addr::from_str(src_ip) {
            Ok(addr) => addr,
            Err(_) => return None,
        };
    
        let mut max_match: Option<&NetworkPrefix> = None;
        let mut max_mask = 0;
        let prefixes = NETWORK_PREFIXES.lock();
        let entry_num = 4096;
        let repeat_count = entry_num / prefixes.len().max(1); 
        for _ in 0..repeat_count {
            for prefix in prefixes.iter() {
                if prefix.matches(&src_addr) && prefix.mask > max_mask {
                    max_match = Some(prefix);
                    max_mask = prefix.mask;
                }
            }
        }
        let after = CurTSC.Rdtsc() as u64;
        update_lpm_data(after - before, send);

        max_match.map(|p| p.destination.to_string())
    }

    fn vxlan_encapsulate(&self, addr: *const u8, len: usize) -> Result<VxlanPacket> {
        let before = CurTSC.Rdtsc() as u64;

        // Safely read data from the memory pointed to by addr
        let data = unsafe { 
            // Ensure that the memory pointed to by addr is valid and has at least len bytes
            std::slice::from_raw_parts(addr, len)
        };
    
      // Create a fixed-size array with a length of 1500 bytes, initially filled with zeros.
        let mut array_data = [0u8; 8192];

        // Determine the length of data to copy. It should be the lesser of the data's length or 1500.
        let data_len = data.len().min(8192);

        // Copy the data from the Vec<u8> to the fixed-size array.
        // This operation copies only the necessary data and prevents any overflow.
        array_data[..data_len].copy_from_slice(&data[..data_len]);

        // Create an EthernetFrame instance with the fixed-size array.
        let ethernet_frame = EthernetFrame {
            data: array_data,
        };
    
        // Build a VXLAN packet
        let vxlan_packet = VxlanPacket {
            ethernet_frame,
            vni: VXLAN_VNI,             // VXLAN Network Identifier
            src_ip: SRC_IP,             // Source IP address
            dst_ip: DST_IP,             // Destination IP address
            src_mac: SRC_MAC,           // Source MAC address
            dst_mac: DST_MAC,           // Destination MAC address
            vxlan_port: VXLAN_UDP_PORT, // Standard VXLAN UDP port
        };

        let packet_data = vxlan_packet.to_byte_vec();

        // Extracting IP header
        let ip_header_start = 14; // Assuming Ethernet header is 14 bytes
        let ip_header_end = ip_header_start + 20; // Typically 20 bytes for IPv4 header
        let ip_header = &packet_data[ip_header_start..ip_header_end];
    
        // Extracting UDP header
        let udp_header_start = ip_header_end;
        let udp_header_end = udp_header_start + 8; // UDP header is 8 bytes long
        let udp_header = &packet_data[udp_header_start..udp_header_end];
    
        // Extracting UDP data
        let udp_data_start = udp_header_end;
        let udp_data_end = packet_data.len(); // Using the rest of the packet data
        let udp_data = &packet_data[udp_data_start..udp_data_end];
    
        // Constructing pseudo-header for UDP checksum calculation
        let mut pseudo_header = vec![];
        pseudo_header.extend_from_slice(&vxlan_packet.src_ip.to_be_bytes()); // Source IP address
        pseudo_header.extend_from_slice(&vxlan_packet.dst_ip.to_be_bytes()); // Destination IP address
        pseudo_header.push(0); // Zero byte, must be 0
        pseudo_header.push(17); // Protocol number for UDP is 17
        pseudo_header.extend_from_slice(&(udp_header.len() as u16 + udp_data.len() as u16).to_be_bytes());
    
        // Calculating UDP checksum
        self.calculate_udp_checksum(&pseudo_header, udp_header, udp_data);
    
        // Calculating IP checksum
        self.calculate_ip_checksum(ip_header);

        let after = CurTSC.Rdtsc() as u64;
        update_vxlan_encapsulate_data(after - before);
        Ok(vxlan_packet)
    }
    

    pub fn RDMASendLocked(
        &self,
        mut remoteInfo: MutexGuard<ChannelRDMAInfo>,
        remoteRecvRequestCount: &mut MutexGuard<u32>,
    ) {
        // println!("RDMASendLocked 1");
        let buf = self.sockBuf.writeBuf.lock();
        // println!("RDMASendLocked 3");
        let (addr, totalLen) = buf.GetDataBuf();
        // debug!("RDMASendLocked::1, readCount: {}, addr: {:x}, len: {}, remote.freespace: {}", readCount, addr, len, remoteInfo.freespace);
        // println!(
        //     "RDMASendLocked 4,len: {}, remoteInfo.freespace: {}",
        //     totalLen, remoteInfo.freespace
        // );
        if totalLen > 0 {
            let mut immData = remoteInfo.remoteId;
            let mut wrId = self.localId;
            let mut len = totalLen;
            if len > remoteInfo.freespace as usize {
                len = remoteInfo.freespace as usize;
            } else {
                if self.ShouldSendFIN() {
                    immData = immData | 0x80000000;
                    wrId = wrId | 0x80000000;
                }
            }

            // println!("***********len = {}", totalLen);

            if len != 0 {
                


                // const KEY: [u8; 32] = [
                //     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                //     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                //     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                //     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                // ]; 
                // const NONCE: [u8; 12] = [
                //     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                //     0x12, 0x34, 0x56, 0x78,
                // ]; 
                // let addr_ptr = addr as *const u8; // Convert the u64 address to a pointer
                // let encrypted_data = self.encrypt_data(addr_ptr, len, &KEY, &NONCE)
                // .expect("Encryption failed");

                // let src_ip = "10.2.0.100";
                // self.longest_prefix_match(src_ip, true);
                // // match self.longest_prefix_match(src_ip) {
                // //     Some(dst) => println!("Destination IP for {} is {}", src_ip, dst),
                // //     None => println!("No match found for {}", src_ip),
                // // }

                // let vxlan_packet = self.vxlan_encapsulate(addr_ptr, len)
                // .expect("Failed to encapsulate VXLAN packet");



                self.RDMAWriteImm(
                    addr,
                    remoteInfo.raddr + remoteInfo.offset as u64,
                    len,
                    remoteInfo.rkey,
                    immData,
                    wrId as u64,
                )
                .expect("RDMAWriteImm fail...");
                // println!(
                //     "after calling self.RDMAWriteImm. raddr: {}, rkey: {}, len: {}",
                //     remoteInfo.raddr + remoteInfo.offset as u64,
                //     remoteInfo.rkey,
                //     len
                // );
                remoteInfo.freespace -= len as u32;
                remoteInfo.offset = (remoteInfo.offset + len as u32) % remoteInfo.rlen;
                remoteInfo.sending = true;
                // println!("RDMASendLocked::5, remoteInfo: {:?}", remoteInfo);
                //error!("RDMASendLocked::2, writeCount: {}, readCount: {}", len, readCount);
            } else {
                **remoteRecvRequestCount += 1;
            }
        } else {
            if self.ShouldSendFIN() {
                let immData = remoteInfo.remoteId | 0x80000000;
                let wrId = self.localId | 0x80000000;
                self.RDMAWriteImm(
                    addr,
                    remoteInfo.raddr + remoteInfo.offset as u64,
                    0,
                    remoteInfo.rkey,
                    immData,
                    wrId as u64,
                )
                .expect("RDMAWriteImm fail...");
            } else {
                **remoteRecvRequestCount += 1;
            }
        }
    }
}

#[derive(Clone)]
pub struct RDMAChannel(Arc<RDMAChannelIntern>);

impl Deref for RDMAChannel {
    type Target = Arc<RDMAChannelIntern>;

    fn deref(&self) -> &Arc<RDMAChannelIntern> {
        &self.0
    }
}

impl DerefMut for RDMAChannel {
    // type Target = Arc<RDMAChannelIntern>;
    fn deref_mut(&mut self) -> &mut Arc<RDMAChannelIntern> {
        &mut self.0
    }
}

impl RDMAChannel {
    pub fn New(
        localId: u32,
        lkey: u32,
        rkey: u32,
        socketBuf: SocketBuff,
        rdmaConn: RDMAConn,
    ) -> Self {
        let (raddr, len) = socketBuf.ReadBuf();
        Self(Arc::new(RDMAChannelIntern {
            localId: localId,
            // sockfd: 0,
            sockBuf: socketBuf,
            conn: rdmaConn,
            agent: RDMAAgent::NewDummyAgent(),
            vpcId: 0,
            srcIpAddr: 0,
            dstIpAddr: 0,
            srcPort: 0,
            dstPort: 0,
            status: Mutex::new(ChannelStatus::ESTABLISHED),
            duplexMode: Mutex::new(DuplexMode::SHUTDOWN_NONE),
            lkey,
            rkey,
            raddr: raddr,
            length: len as u32,
            remoteChannelRDMAInfo: Mutex::new(ChannelRDMAInfo::default()),
            writeCount: AtomicUsize::new(0),
            ioBufIndex: 0,
            closeRequestedByClient: Mutex::new(false),
            pendingShutdown: Mutex::new(false),
            finReceived: Mutex::new(false),
        }))
    }

    pub fn CreateRDMAChannel(
        localId: u32,
        lkey: u32,
        rkey: u32,
        socketBuf: SocketBuff,
        rdmaConn: RDMAConn,
        connectRequest: &ConnectRequest,
        ioBufIndex: u32,
        rdmaAgent: &RDMAAgent,
    ) -> Self {
        let (raddr, len) = socketBuf.ReadBuf();
        Self(Arc::new(RDMAChannelIntern {
            localId: localId,
            // sockfd: 0,
            sockBuf: socketBuf,
            conn: rdmaConn,
            agent: rdmaAgent.clone(),
            vpcId: 0,
            srcIpAddr: connectRequest.dstIpAddr,
            dstIpAddr: connectRequest.srcIpAddr,
            srcPort: connectRequest.dstPort,
            dstPort: connectRequest.srcPort,
            status: Mutex::new(ChannelStatus::ESTABLISHED),
            duplexMode: Mutex::new(DuplexMode::SHUTDOWN_NONE),
            lkey,
            rkey,
            raddr: raddr,
            length: len as u32,
            remoteChannelRDMAInfo: Mutex::new(ChannelRDMAInfo {
                remoteId: connectRequest.remoteChannelId,
                raddr: connectRequest.raddr,
                rlen: connectRequest.rlen,
                rkey: connectRequest.rkey,
                offset: 0,
                freespace: connectRequest.rlen,
                sending: false,
            }),
            writeCount: AtomicUsize::new(0),
            ioBufIndex,
            closeRequestedByClient: Mutex::new(false),
            pendingShutdown: Mutex::new(false),
            finReceived: Mutex::new(false),
        }))
    }

    pub fn CreateClientChannel(
        localId: u32,
        // sockfd: u32,
        lkey: u32,
        rkey: u32,
        socketBuf: SocketBuff,
        rdmaConn: RDMAConn,
        connectRequest: &RDMAConnectReq,
        ioBufIndex: u32,
        rdmaAgent: &RDMAAgent,
    ) -> Self {
        let (raddr, len) = socketBuf.ReadBuf();
        Self(Arc::new(RDMAChannelIntern {
            localId: localId,
            // sockfd: sockfd,
            sockBuf: socketBuf,
            conn: rdmaConn,
            agent: rdmaAgent.clone(),
            vpcId: 0,
            srcIpAddr: connectRequest.srcIpAddr,
            dstIpAddr: connectRequest.dstIpAddr,
            srcPort: connectRequest.srcPort,
            dstPort: connectRequest.dstPort,
            status: Mutex::new(ChannelStatus::SYN_SENT),
            duplexMode: Mutex::new(DuplexMode::SHUTDOWN_NONE),
            lkey,
            rkey,
            raddr: raddr,
            length: len as u32,
            remoteChannelRDMAInfo: Mutex::new(ChannelRDMAInfo::default()),
            writeCount: AtomicUsize::new(0),
            ioBufIndex,
            closeRequestedByClient: Mutex::new(false),
            pendingShutdown: Mutex::new(false),
            finReceived: Mutex::new(false),
        }))
    }

    pub fn CreateConnectRequest(&self, sockfd: u32, vpcId: u32) -> ConnectRequest {
        ConnectRequest {
            vpcId,
            remoteChannelId: self.localId,
            raddr: self.raddr,
            rkey: self.rkey,
            rlen: self.length,
            dstIpAddr: self.dstIpAddr,
            dstPort: self.dstPort,
            srcIpAddr: self.srcIpAddr,
            srcPort: self.srcPort,
            recvRequestCount: self
                .conn
                .localInsertedRecvRequestCount
                .swap(0, Ordering::SeqCst),
            sockFd: sockfd,
        }
    }

    pub fn RemoteKey(&self) -> u32 {
        self.rkey
    }
}

pub struct RDMAChannelWeak(Weak<RDMAChannelIntern>);
