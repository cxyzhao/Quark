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

use super::id_mgr::{ChannelIdMgr, IdMgr};
use super::qlib::rdma_share::*;
use super::rdma::*;
use super::rdma_agent::*;
use super::rdma_channel::*;
use super::rdma_conn::*;
use super::rdma_ctrlconn::*;
use core::sync::atomic::Ordering;
use lazy_static::lazy_static;
use spin::Mutex;
use std::collections::HashMap;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::{env, mem, ptr, thread, time};

lazy_static! {
    pub static ref RDMA_SRV: RDMASrv = RDMASrv::New();
    pub static ref RDMA_CTLINFO: CtrlInfo = CtrlInfo::default();
    //pub static ref RDMA_SRV_SHARED_REGION: ShareRegion = ShareRegion::default();
}

pub const RECV_UDP_COUNT: u32 = 2000;

#[derive(Clone, Debug)]
pub enum SrvEndPointStatus {
    Binded,
    Listening,
}

pub struct SrvEndpoint {
    //pub srvEndpointId: u32, // to be returned as bind
    pub agentId: u32,
    pub sockfd: u32,
    pub endpoint: Endpoint,
    pub status: SrvEndPointStatus, //TODO: double check whether it's needed or not
                                   //pub acceptQueue: [RDMAChannel; 5], // hold rdma channel which can be assigned.
}

#[derive(Debug)]
pub struct SrvEndpointUsingPodId {
    //pub srvEndpointId: u32, // to be returned as bind
    pub agentId: u32,
    pub sockfd: u32,
    pub podId: [u8; 64],
    pub port: u16,
    pub status: SrvEndPointStatus, //TODO: double check whether it's needed or not
                                   //pub acceptQueue: [RDMAChannel; 5], // hold rdma channel which can be assigned.
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct EndpointUsingPodId {
    // same as vpcId
    pub podId: [u8; 64],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VpcIpAddr {
    pub vpcId: u32,
    pub ipAddr: u32,
}

pub struct RDMAControlChannelRegion {
    // data buf for sockbuf, it will be mapped in the rdma MR
    pub iobufs: [IOBuf; IO_BUF_COUNT],

    // metadata region for the sockbuf
    pub ioMetas: [IOMetas; IO_BUF_COUNT],
}

pub struct RDMASrv {
    // epoll fd
    pub epollFd: i32,

    // unix socket srv fd
    pub unixSockfd: i32,

    // tcp socket srv fd
    pub tcpSockfd: i32,

    // eventfd which used by rdma client to trigger RDMA srv
    pub eventfd: i32,

    // srv memory region memfd shared with RDMAclient
    pub srvMemfd: i32,

    // srv memory region shared with all RDMAClient
    pub srvMemRegion: MemRegion,

    // glocal udp memory region
    pub udpMemRegion: MemRegion,

    // rdma connects: remote node ipaddr --> RDMAConn
    pub conns: Mutex<HashMap<u32, RDMAConn>>,

    // todo: tbd: need it?
    // rdma connects: virtual subnet ipaddr --> RDMAConn
    // pub vipMapping: HashMap<u32, RDMAConn>,

    // rdma channels: channelId --> RDMAChannel
    pub channels: Mutex<HashMap<u32, RDMAChannel>>,

    // rdma control channels: qpNum -> RDMAChannel
    pub controlChannels: Mutex<HashMap<u32, RDMAControlChannel>>,
    // qpNum -> controlChannel's channel
    pub controlChannels2: Mutex<HashMap<u32, RDMAChannel>>,

    // agents: agentId -> RDMAAgent
    pub agents: Mutex<HashMap<u32, RDMAAgent>>,

    pub sockToAgentIds: Mutex<HashMap<i32, u32>>,

    // the bitmap to expedite ready container search
    pub shareRegion: &'static ShareRegion,

    // keep track of server endpoint on current node
    pub srvEndPoints: Mutex<HashMap<Endpoint, SrvEndpoint>>,

    // use pod id to track srvEndpoint
    pub srvPodIdEndpoints: Mutex<HashMap<EndpointUsingPodId, SrvEndpointUsingPodId>>,

    pub currNode: Node,

    pub channelIdMgr: Mutex<ChannelIdMgr>,

    pub agentIdMgr: Mutex<IdMgr>,
    //TODO: indexes allocated for io buffer.
    pub controlRegion: &'static RDMAControlChannelRegion,
    pub controlChannelRegionAddress: MemRegion,
    pub controlBufIdMgr: Mutex<IdMgr>,
    pub keys: Vec<[u32; 2]>,
    pub controlMemoryRegion: MemoryRegion,
    pub udpMemoryRegion: MemoryRegion,
    pub udpQP: QueuePair,
    pub udpBufferAllocator: Mutex<UDPBufferAllocator>,
    pub podIdToAgents: Mutex<HashMap<[u8; 64], RDMAAgent>>,
    pub vpcIpAddrToAgents: Mutex<HashMap<VpcIpAddr, RDMAAgent>>,
    // pub timestamps: Mutex<Vec<i64>>,
}

impl Drop for RDMASrv {
    fn drop(&mut self) {
        //TODO: This is not called because it's global static
        println!("drop RDMASrv");
        unsafe {
            //TODO: unregister MR
            libc::munmap(
                self.controlChannelRegionAddress.addr as *mut libc::c_void,
                self.controlChannelRegionAddress.len as usize,
            );
            libc::munmap(
                self.srvMemRegion.addr as *mut libc::c_void,
                self.srvMemRegion.len as usize,
            );
            libc::munmap(
                self.udpMemRegion.addr as *mut libc::c_void,
                self.udpMemRegion.len as usize,
            );
        }
    }
}

impl RDMASrv {
    pub fn New() -> Self {
        println!("RDMASrv::New");
        // RDMA.Init("", 1);
        let controlSize = mem::size_of::<RDMAControlChannelRegion>();
        let contrlAddr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                controlSize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if contrlAddr == libc::MAP_FAILED {
            panic!("failed to mmap control region");
        }

        let udpPacketExtendedSize = mem::size_of::<UDPPacket>() + 40;
        let udpBufferSize = udpPacketExtendedSize * RECV_UDP_COUNT as usize;
        let udpBufferAddr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                udpBufferSize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if udpBufferAddr == libc::MAP_FAILED {
            panic!("failed to mmap udp buffer");
        }

        // println!(
        //     "contrlAddr : 0x{:x}, controlSize is: {}",
        //     contrlAddr as u64, controlSize
        // );

        let memfdname = CString::new("RDMASrvMemFd").expect("CString::new failed for RDMASrvMemFd");
        let memfd = unsafe { libc::memfd_create(memfdname.as_ptr(), libc::MFD_ALLOW_SEALING) };
        // println!("memfd::{}", memfd);
        if memfd == -1 {
            panic!(
                "fail to create memfd, error is: {}",
                std::io::Error::last_os_error()
            );
        }
        let size = mem::size_of::<ShareRegion>();
        let _ret = unsafe { libc::ftruncate(memfd, size as i64) };
        let shareRegionAddr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                memfd,
                0,
            )
        };

        if shareRegionAddr as i64 == -1 {
            panic!(
                "fail to mmap share region, error is: {}",
                std::io::Error::last_os_error()
            );
        }

        //start from 2M registration.
        let controlMR = RDMA
            .CreateMemoryRegion(contrlAddr as u64, 2 * 1024 * 1024)
            .unwrap();
        let udpMR = RDMA
            .CreateMemoryRegion(udpBufferAddr as u64, udpBufferSize)
            .unwrap();
        let udpQP = RDMA.CreateUDQueuePair().expect("Create UD QP failed...");
        udpQP.SetupUDQP(&RDMA).expect("SetupUDQP fail...");

        for i in 0..RECV_UDP_COUNT {
            let addr = udpBufferAddr as u64 + (i * udpPacketExtendedSize as u32) as u64;
            udpQP
                .PostRecv(i as u64, addr, udpMR.LKey(), udpPacketExtendedSize as u32)
                .expect("SetupUDQP PostRecv fail");
        }

        let udpBufferAllocator = Mutex::new(UDPBufferAllocator::New(
            udpBufferAddr as u64,
            UDP_SENT_PACKET_COUNT as u32,
        ));

        return Self {
            epollFd: 0,
            unixSockfd: 0,
            tcpSockfd: 0,
            eventfd: unsafe { libc::eventfd(0, 0) },
            srvMemfd: memfd,
            srvMemRegion: MemRegion {
                addr: shareRegionAddr as u64,
                len: size as u64,
            },
            udpMemRegion: MemRegion {
                addr: udpBufferAddr as u64,
                len: udpBufferSize as u64,
            },
            conns: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            agents: Mutex::new(HashMap::new()),
            shareRegion: unsafe {
                let addr = shareRegionAddr as *mut ShareRegion;
                &mut (*addr)
            },
            srvEndPoints: Mutex::new(HashMap::new()),
            srvPodIdEndpoints: Mutex::new(HashMap::new()),
            currNode: Node::default(),
            channelIdMgr: Mutex::new(ChannelIdMgr::Init(1, 1000)),
            agentIdMgr: Mutex::new(IdMgr::Init(0, 1000)),
            controlRegion: unsafe {
                let addr = contrlAddr as *mut RDMAControlChannelRegion;
                &mut (*addr)
            },
            controlChannelRegionAddress: MemRegion {
                addr: contrlAddr as u64,
                len: controlSize as u64,
            },
            controlBufIdMgr: Mutex::new(IdMgr::Init(1, 1024)),
            keys: vec![[controlMR.LKey(), controlMR.RKey()]],
            controlChannels: Mutex::new(HashMap::new()),
            controlChannels2: Mutex::new(HashMap::new()),
            sockToAgentIds: Mutex::new(HashMap::new()),
            controlMemoryRegion: controlMR,
            udpMemoryRegion: udpMR,
            udpQP,
            udpBufferAllocator,
            vpcIpAddrToAgents: Mutex::new(HashMap::new()),
            podIdToAgents: Mutex::new(HashMap::new()),
            // timestamps: Mutex::new(Vec::with_capacity(16)),
        };
    }

    pub fn getRDMAChannel(&self, channelId: u32) -> Option<RDMAChannel> {
        match self.channels.lock().get(&channelId) {
            None => None,
            Some(rdmaChannel) => Some(rdmaChannel.clone()),
        }
    }

    pub fn ProcessRDMAWriteImmFinish(&self, channelId: u32, qpNum: u32) {
        let finSent = channelId & 0x80000000 == 0x80000000;
        let channelId = channelId & 0x7FFFFFFF;
        if channelId != 0 {
            let channel = self.channels.lock().get(&channelId).unwrap().clone();
            // {
            //     let channels = self.channels.lock();
            //     let item1 = channels.get(&channelId).unwrap();
            //     channel = item1.clone();
            // }

            channel.ProcessRDMAWriteImmFinish(finSent);

            // match self.channels.lock().get(&channelId) {
            // match item {
            //     None => {
            //         panic!(
            //             "ProcessRDMAWriteImmFinish get unexpected channelId: {}",
            //             channelId
            //         );
            //     }
            //     Some(channel) => {
            //         channel.ProcessRDMAWriteImmFinish(finSent);
            //     }
            // }
        } else {
            match self.controlChannels.lock().get(&qpNum) {
                None => {
                    panic!("ProcessRDMAWriteImmFinish get unexpected qpNum: {}", qpNum);
                }
                Some(channel) => {
                    channel.ProcessRDMAWriteImmFinish();
                }
            }
        }
    }

    pub fn ProcessRDMARecvWriteImm(&self, channelId: u32, qpNum: u32, recvCount: u32) {
        // println!(
        //     "RDMASrv::ProcessRDMARecvWriteImm, 1 channelId: {}, qpNum: {}, recvCount: {}",
        //     channelId, qpNum, recvCount
        // );
        let finReceived = channelId & 0x80000000 == 0x80000000;
        let channelId = channelId & 0x7FFFFFFF;

        // println!(
        //     "RDMASrv::ProcessRDMARecvWriteImm, 2 channelId: {}, finReceived: {}",
        //     channelId, finReceived
        // );
        if channelId != 0 {
            let channelOption;
            let channels = self.channels.lock();
            channelOption = channels.get(&channelId);
            match channelOption {
                None => {
                    error!(
                        "ProcessRDMARecvWriteImm get unexpected channelId: {}",
                        channelId
                    );
                }
                Some(channel) => {
                    let channelClone = channel.clone();
                    drop(channels);
                    channelClone.ProcessRDMARecvWriteImm(qpNum, recvCount as u64, finReceived);
                }
            }
        } else {
            match RDMA_SRV.controlChannels.lock().get(&qpNum) {
                //where lock end??
                None => {
                    panic!("ProcessRDMAWriteImmFinish get unexpected qpNum: {}", qpNum);
                }
                Some(channel) => {
                    channel.ProcessRDMARecvWriteImm(qpNum, recvCount as u64);
                }
            }
        }
    }

    pub fn ProcessRDMARecv(&self, _qpNum: u32, wrId: u64, _len: u32) {
        // error!(
        //     "ProcessRDMARecv, 1, qpNum: {}, wrId: {}, len: {}",
        //     qpNum, wrId, len
        // );

        let laddr = self.udpMemRegion.addr + wrId * (mem::size_of::<UDPPacket>() + 40) as u64 + 40;
        // let _payloadLen = len - 40;
        // let mut i = 0;
        // loop {
        //     let addr = laddr + i * 8;
        //     println!("addr{}: 0x{:x}-> 0x{:x}", i, addr, unsafe {
        //         &mut *(addr as *mut u64)
        //     });
        //     i += 1;
        //     if i == 10 {
        //         break;
        //     }
        // }
        let udpPacket = unsafe { &(*(laddr as *const UDPPacket)) };
        // debug!("RDMASrv::ProcessRDMARecv, udpPacket: {:?}", udpPacket);
        if RDMA_CTLINFO.isK8s {
            match self.vpcIpAddrToAgents.lock().get(&VpcIpAddr {
                vpcId: udpPacket.vpcId,
                ipAddr: udpPacket.dstIpAddr,
            }) {
                Some(rdmaAgent) => {
                    rdmaAgent.HandleUDPPacketRecv(udpPacket);
                    self.udpBufferAllocator.lock().ReturnBuffer(wrId as u32);
                }
                None => {}
            }
        } else {
            // Test hook
            for (_agentId, rdmaAgent) in self.agents.lock().iter() {
                rdmaAgent.HandleUDPPacketRecv(udpPacket);
                self.udpBufferAllocator.lock().ReturnBuffer(wrId as u32);
                break;
            }
        }
    }

    pub fn ProcessRDMASend(&self, wrId: u64) {
        let agentId = (wrId >> 32) as u32;
        let udpBuffIdx = (wrId & 0xFFFFFFFF) as u32;
        // error!("ProcessRDMASend, 1, wrId: {}, agentId: {}, udpBuffIdx: {}", wrId, agentId, udpBuffIdx);
        match RDMA_SRV.agents.lock().get(&agentId) {
            Some(rdmaAgent) => {
                rdmaAgent.SendResponse(RDMAResp {
                    user_data: 0,
                    msg: RDMARespMsg::RDMAReturnUDPBuff(RDMAReturnUDPBuff { udpBuffIdx }),
                });
            }
            None => {
                panic!("ProcessRDMASend, could not find agentId: {}", agentId)
            }
        }
    }

    // pub fn HandleClientRequest(&self) -> usize {
    //     let agentIds = self.shareRegion.getAgentIds();
    //     // println!("agentIds: {:?}", agentIds);
    //     let rdmaAgents = self.agents.lock();
    //     let mut count = 0;
    //     for agentId in agentIds.iter() {
    //         match rdmaAgents.get(agentId) {
    //             Some(rdmaAgent) => {
    //                 // rdmaAgent
    //                 count += rdmaAgent.HandleClientRequest();
    //             }
    //             None => {
    //                 println!("RDMA agent with id {} doesn't exist", agentId);
    //             }
    //         }
    //     }
    //     count
    // }

    pub fn HandleClientRequest(&self) -> usize {
        let mut count = 0;
        for l1idx in 0..8 {
            // println!("l1idx: {}", l1idx);
            let mut l1;
            #[cfg(offload = "yes")]{
                l1 = self.shareRegion.bitmap.l1bitmap[l1idx].load(Ordering::SeqCst);
            }
            #[cfg(not(offload = "yes"))]{
                l1 = self.shareRegion.bitmap.l1bitmap[l1idx].swap(0, Ordering::SeqCst);
            }
            // println!("l1: {:x}", l1);
            for l1pos in 0..64 {
                if l1 == 0 {
                    // println!("break for l1idx: {}", l1idx);
                    break;
                }
                if l1 % 2 == 1 {
                    let l2idx = l1idx * 64 + l1pos;
                    // println!("l2idx: {}", l2idx);
                    if l2idx > 502 {
                        break;
                    }
                    let mut l2;
                    #[cfg(offload = "yes")]{
                        l2 = self.shareRegion.bitmap.l2bitmap[l2idx as usize].load(Ordering::SeqCst);
                    }
                    #[cfg(not(offload = "yes"))]{
                        l2 = self.shareRegion.bitmap.l2bitmap[l2idx as usize].swap(0, Ordering::SeqCst);
                    }
                    // println!("l2: {:x}", l2);
                    for l2pos in 0..64 {
                        if l2 == 0 {
                            // println!("before break, l2pos: {}", l2pos);
                            break;
                        }
                        if l2 % 2 == 1 {
                            let agentId = (l2idx * 64 + l2pos) as u32;
                            let rdmaAgents = self.agents.lock();
                            match rdmaAgents.get(&agentId) {
                                Some(rdmaAgent) => {
                                    // rdmaAgent
                                    count += rdmaAgent.HandleClientRequest();
                                }
                                None => {
                                    println!("RDMA agent with id {} doesn't exist", agentId);
                                }
                            }
                        }
                        l2 >>= 1;
                    }
                }
                l1 >>= 1
            }
        }

        count
    }

    // pub fn CreateRDMAChannel(&self, agentId: u32) {
    //     let channelId = self.channelIdMgr.lock().AllocId();

    // }

    pub fn ExistsConnection(&self, ip: &u32) -> bool {
        self.conns.lock().contains_key(ip)
    }
}

// scenarios:
// a. init
// b. input:
//      1. srv socket accept -> init client connection
//      2. srv tcp socket accept -> init peer connection
//      3. client submit queue
//      4. rdma work complete trigger
//      5. connection mgr callback
// c. de-construction
//      1. connection mgr disconnect
//      2. tcp connection close
//      3. rdma connection disconnect (keepalive?)
// request/response type
