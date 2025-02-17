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

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]
#![feature(proc_macro_hygiene)]
#![feature(naked_functions)]
#![allow(bare_trait_objects)]
#![feature(map_first_last)]
#![allow(non_camel_case_types)]
#![allow(deprecated)]
#![feature(thread_id_value)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![feature(core_intrinsics)]
#![recursion_limit = "256"]

extern crate alloc;
extern crate bit_field;
extern crate core_affinity;
extern crate errno;

#[macro_use]
extern crate serde_derive;
extern crate cache_padded;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate scopeguard;

#[macro_use]
extern crate lazy_static;

extern crate libc;
extern crate spin;
extern crate x86_64;
#[macro_use]
extern crate log;
extern crate caps;
extern crate fs2;
extern crate regex;
extern crate simplelog;
extern crate tabwriter;

#[macro_use]
pub mod print;

#[macro_use]
pub mod asm;
pub mod kernel_def;
pub mod qlib;

pub mod common;
pub mod constants;
pub mod rdma_ctrlconn;
pub mod rdma_def;
pub mod ingress_informer;
pub mod rdma_ingress_informer;
pub mod service_informer;
pub mod unix_socket_def;

use self::qlib::ShareSpaceRef;
use alloc::slice;
use alloc::sync::Arc;
use fs2::FileExt;
use spin::Mutex;
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
pub static SHARE_SPACE: ShareSpaceRef = ShareSpaceRef::New();
use self::qlib::mem::list_allocator::*;
use crate::qlib::rdma_share::*;
use common::EpollEvent;
use common::*;
use qlib::linux_def::*;
use qlib::rdma_svc_cli::*;
use qlib::socket_buf::{SocketBuff, SocketBuffIntern};
use qlib::unix_socket::UnixSocket;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::{env, mem, ptr, thread, time};
use rdma_ctrlconn::*;
use ingress_informer::IngressInformer;
use rdma_ingress_informer::RdmaIngressInformer;
use service_informer::ServiceInformer;
use crate::constants::*;

pub static GLOBAL_ALLOCATOR: HostAllocator = HostAllocator::New();

lazy_static! {
    pub static ref GLOBAL_LOCK: Mutex<()> = Mutex::new(());
    pub static ref RDMA_CTLINFO: CtrlInfo = CtrlInfo::default();
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    let gatewayCli: GatewayClient;
    let mut unix_sock_path = "/var/quarkrdma/rdma_srv_socket";
    if args.len() > 1 {
        unix_sock_path = args.get(1).unwrap(); //"/tmp/rdma_srv1";
    }
    gatewayCli = GatewayClient::initialize(unix_sock_path); //TODO: add 2 address from quark.

    let cliEventFd = gatewayCli.rdmaSvcCli.cliEventFd;
    unblock_fd(cliEventFd);
    unblock_fd(gatewayCli.rdmaSvcCli.srvEventFd);
    
    let epoll_fd = epoll_create().expect("can create epoll queue");
    RDMA_CTLINFO.epoll_fd_set(epoll_fd);
    epoll_add(epoll_fd, cliEventFd, read_event(cliEventFd as u64))?;
    RDMA_CTLINFO.fds_insert(cliEventFd, FdType::ClientEvent);

    tokio::spawn(async {
        while !RDMA_CTLINFO.isCMConnected_get() {
            let mut ingress_informer = IngressInformer::new();
            match ingress_informer.run().await {
                Err(e) => {
                    println!("Error to handle ingresses: {:?}", e);
                    thread::sleep_ms(1000);
                }
                Ok(_) => (),
            };
        }
    });

    tokio::spawn(async {
        while !RDMA_CTLINFO.isCMConnected_get() {
            thread::sleep_ms(1000);
        }
        let mut rdma_ingress_informer = RdmaIngressInformer::new();
        match rdma_ingress_informer.run().await {
            Err(e) => {
                println!("Error to handle rdma ingresses: {:?}", e);
                thread::sleep_ms(1000);
            }
            Ok(_) => (),
        };
    });

    tokio::spawn(async {
        while !RDMA_CTLINFO.isCMConnected_get() {
            thread::sleep_ms(1000);
        }
        let mut service_informer = ServiceInformer::new();
        match service_informer.run().await {
            Err(e) => {
                println!("Error to handle services: {:?}", e);
            }
            Ok(_) => (),
        };
    });

    // set up TCP Server to wait for incoming connection
    let server_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    RDMA_CTLINFO.fds_insert(server_fd, FdType::TCPSocketServer(INCLUSTER_INGRESS_PORT));
    unblock_fd(server_fd);
    epoll_add(epoll_fd, server_fd, read_write_event(server_fd as u64))?;    

    unsafe {
        let serv_addr: libc::sockaddr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: INCLUSTER_INGRESS_PORT.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([0, 0, 0, 0]).to_be(),
            },
            sin_zero: mem::zeroed(),
        };

        let result = libc::bind(
            server_fd,
            &serv_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of_val(&serv_addr) as u32,
        );
        if result < 0 {
            libc::close(server_fd);
            panic!("last OS error: {:?}", Error::last_os_error());
        }
        libc::listen(server_fd, 128);
    }

    wait(epoll_fd, &gatewayCli);

    return Ok(());
}

fn wait(epoll_fd: i32, gatewayCli: &GatewayClient) {
    let mut events: Vec<EpollEvent> = Vec::with_capacity(1024);
    let mut sockFdMappings: HashMap<u32, i32> = HashMap::new(); // mapping between sockfd maintained by rdmaSvcCli and fd for incoming requests.
    loop {
        events.clear();
        {
            gatewayCli
                .rdmaSvcCli
                .cliShareRegion
                .lock()
                .clientBitmap
                .store(1, Ordering::SeqCst);
        }
        let res = match syscall!(epoll_wait(
            epoll_fd,
            events.as_mut_ptr() as *mut libc::epoll_event,
            1024,
            -1 as libc::c_int,
        )) {
            Ok(v) => v,
            Err(e) => panic!("error during epoll wait: {}", e),
        };

        unsafe { events.set_len(res as usize) };

        for ev in &events {
            let event_data = RDMA_CTLINFO.fds_get(&(ev.U64 as i32));
            match event_data {
                Some(FdType::TCPSocketServer(_port)) => {
                    let mut stream_fd;
                    let mut cliaddr: libc::sockaddr_in = unsafe { mem::zeroed() };
                    let mut len = mem::size_of_val(&cliaddr) as u32;
                    let mut oriAddr: libc::sockaddr_in = unsafe { mem::zeroed() };
                    let mut oriLen = mem::size_of_val(&oriAddr) as u32;
                    loop {
                        unsafe {
                            stream_fd = libc::accept(
                                ev.U64 as i32,
                                &mut cliaddr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                                &mut len,
                            );
                        }
                        if stream_fd > 0 {
                            unblock_fd(stream_fd);
                            let _ret =
                                epoll_add(epoll_fd, stream_fd, read_write_event(stream_fd as u64));
                            
                            let mut ipAddr = 0;
                            let mut port = 0;
                            if _port == INCLUSTER_INGRESS_PORT {
                                unsafe {
                                    let oriFd = libc::getsockopt(
                                        stream_fd,
                                        SOL_IP,
                                        SO_ORIGINAL_DST,
                                        &mut oriAddr as *mut libc::sockaddr_in as *mut libc::sockaddr as *mut libc::c_void,
                                        &mut oriLen);
                                    if oriFd >= 0 {
                                        ipAddr = oriAddr.sin_addr.s_addr;
                                        port = oriAddr.sin_port.to_be();
                                        println!("Redirect ingress traffic for {}/{}",ipAddr, port);
                                    } else {
                                        error!("error to retrieve original destination.");
                                        break;
                                    }
                                }
                            } else {
                                match RDMA_CTLINFO.GetRdmaIngressByPort(_port) {
                                    Some(rdmaIngress) => {
                                        ipAddr = RDMA_CTLINFO.GetServiceIpFromName(rdmaIngress.service).unwrap();
                                        port = rdmaIngress.targetPortNumber;
                                        println!("GetRdmaIngressByPort found _port {} ipAddr {}, port {}", _port, ipAddr, port);
                                    }
                                    None => {
                                        error!("No RdmaIngress defined for port {}.", _port);
                                    },
                                }
                            }

                            if ipAddr > 0 {
                                let sockfd = gatewayCli.sockIdMgr.lock().AllocId().unwrap();
                                let _ret = gatewayCli.connect(
                                    sockfd,
                                    ipAddr.to_be(),
                                    port.to_be(),
                                );
                                RDMA_CTLINFO.fds_insert(stream_fd, FdType::TCPSocketConnect(sockfd));
                                sockFdMappings.insert(sockfd, stream_fd);
                            }
                        } else {
                            break;
                        }
                    }
                }
                Some(FdType::TCPSocketConnect(sockfd)) => {
                    let mut sockInfo = gatewayCli.GetDataSocket(&sockfd);
                    if !matches!(*sockInfo.status.lock(), SockStatus::ESTABLISHED) {
                        continue;
                    }
                    if ev.Events & EVENT_IN as u32 != 0 {
                        gatewayCli.ReadFromSocket(&mut sockInfo, &sockFdMappings);
                    }
                    if ev.Events & EVENT_OUT as u32 != 0 {
                        gatewayCli.WriteToSocket(&mut sockInfo, &sockFdMappings);
                    }
                }
                Some(FdType::ClientEvent) => {
                    loop {
                        let request = gatewayCli.rdmaSvcCli.cliShareRegion.lock().cq.Pop();
                        match request {
                            Some(cq) => match cq.msg {
                                RDMARespMsg::RDMAConnect(response) => {
                                    let ioBufIndex = response.ioBufIndex as usize;
                                    let mut sockFdInfos = gatewayCli.dataSockFdInfos.lock();
                                    let sockInfo = sockFdInfos.get_mut(&response.sockfd).unwrap();
                                    // println!("RDMARespMsg::RDMAConnect, sockfd: {}, channelId: {}", sockInfo.fd, response.channelId);
                                    {
                                        let shareRegion =
                                            gatewayCli.rdmaSvcCli.cliShareRegion.lock();
                                        let sockInfo = DataSock::New(
                                            sockInfo.fd, //Allocate fd
                                            sockInfo.srcIpAddr,
                                            sockInfo.srcPort,
                                            sockInfo.dstIpAddr,
                                            sockInfo.dstPort,
                                            SockStatus::ESTABLISHED,
                                            response.channelId,
                                            SocketBuff(Arc::new(
                                                SocketBuffIntern::InitWithShareMemory(
                                                    MemoryDef::DEFAULT_BUF_PAGE_COUNT,
                                                    &shareRegion.ioMetas[ioBufIndex].readBufAtoms
                                                        as *const _
                                                        as u64,
                                                    &shareRegion.ioMetas[ioBufIndex].writeBufAtoms
                                                        as *const _
                                                        as u64,
                                                    &shareRegion.ioMetas[ioBufIndex].consumeReadData
                                                        as *const _
                                                        as u64,
                                                    &shareRegion.iobufs[ioBufIndex].read as *const _
                                                        as u64,
                                                    &shareRegion.iobufs[ioBufIndex].write
                                                        as *const _
                                                        as u64,
                                                    false,
                                                ),
                                            )),
                                        );
                                        sockFdInfos.insert(sockInfo.fd, sockInfo);
                                    }

                                    let sockInfo = sockFdInfos.get_mut(&response.sockfd).unwrap();
                                    gatewayCli
                                        .channelToSockInfos
                                        .lock()
                                        .insert(response.channelId, sockInfo.clone());

                                    gatewayCli.ReadFromSocket(sockInfo, &sockFdMappings);
                                }
                                RDMARespMsg::RDMAAccept(response) => {
                                    let mut sockFdInfos = gatewayCli.serverSockFdInfos.lock();
                                    let sockInfo = sockFdInfos.get_mut(&response.sockfd).unwrap();

                                    let ioBufIndex = response.ioBufIndex as usize;
                                    let dataSockFd = gatewayCli.sockIdMgr.lock().AllocId().unwrap();
                                    let shareRegion = gatewayCli.rdmaSvcCli.cliShareRegion.lock();
                                    let dataSockInfo = DataSock::New(
                                        dataSockFd, //Allocate fd
                                        sockInfo.srcIpAddr,
                                        sockInfo.srcPort,
                                        response.dstIpAddr,
                                        response.dstPort,
                                        SockStatus::ESTABLISHED,
                                        response.channelId,
                                        SocketBuff(Arc::new(
                                            SocketBuffIntern::InitWithShareMemory(
                                                MemoryDef::DEFAULT_BUF_PAGE_COUNT,
                                                &shareRegion.ioMetas[ioBufIndex].readBufAtoms
                                                    as *const _
                                                    as u64,
                                                &shareRegion.ioMetas[ioBufIndex].writeBufAtoms
                                                    as *const _
                                                    as u64,
                                                &shareRegion.ioMetas[ioBufIndex].consumeReadData
                                                    as *const _
                                                    as u64,
                                                &shareRegion.iobufs[ioBufIndex].read as *const _
                                                    as u64,
                                                &shareRegion.iobufs[ioBufIndex].write as *const _
                                                    as u64,
                                                false,
                                            ),
                                        )),
                                    );

                                    gatewayCli
                                        .dataSockFdInfos
                                        .lock()
                                        .insert(dataSockFd, dataSockInfo.clone());
                                    sockInfo.acceptQueue.lock().EnqSocket(dataSockFd);
                                    gatewayCli
                                        .channelToSockInfos
                                        .lock()
                                        .insert(response.channelId, dataSockInfo.clone());
                                }
                                RDMARespMsg::RDMANotify(response) => {
                                    if response.event & EVENT_IN != 0 {
                                        let mut sockInfo =
                                            gatewayCli.GetChannelSocket(&response.channelId);
                                        gatewayCli.WriteToSocket(&mut sockInfo, &sockFdMappings);
                                    }
                                    if response.event & EVENT_OUT != 0 {
                                        let mut sockInfo =
                                            gatewayCli.GetChannelSocket(&response.channelId);
                                        gatewayCli.ReadFromSocket(&mut sockInfo, &sockFdMappings);
                                    }
                                }
                                RDMARespMsg::RDMAFinNotify(response) => {
                                    let mut sockInfo =
                                        gatewayCli.GetChannelSocket(&response.channelId);
                                    if response.event & FIN_RECEIVED_FROM_PEER != 0 {
                                        *sockInfo.finReceived.lock() = true;
                                        gatewayCli.WriteToSocket(&mut sockInfo, &sockFdMappings);
                                    }
                                }
                                RDMARespMsg::RDMAReturnUDPBuff(_response) => {
                                    // TODO Handle UDP
                                }
                                RDMARespMsg::RDMARecvUDPPacket(_udpBuffIdx) => todo!()
                            },
                            None => {
                                break;
                            }
                        }
                    }
                }
                None => {}
            }
        }
    }
}
