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
// #[path = "../../qlib/mod.rs"]
// pub mod qlib;

pub mod id_mgr;
pub mod rdma;
pub mod rdma_agent;
pub mod rdma_channel;
pub mod rdma_conn;
pub mod rdma_ctrlconn;
pub mod rdma_def;
pub mod rdma_srv;
pub mod unix_socket_def;

pub mod common;
pub mod configmap_informer;
pub mod constants;
pub mod endpoints_informer;
pub mod node_informer;
pub mod pod_informer;
pub mod service_informer;
use std::ffi::CStr;

use crate::qlib::bytestream::ByteStream;
use crate::rdma_srv::RDMA_CTLINFO;
use crate::rdma_srv::RDMA_SRV;

use self::qlib::ShareSpaceRef;
use alloc::slice;
use byteorder::WriteBytesExt;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
pub static SHARE_SPACE: ShareSpaceRef = ShareSpaceRef::New();
use self::qlib::mem::list_allocator::*;
use crate::qlib::rdma_share::*;
use crate::rdma::RDMA;
use common::*;
use configmap_informer::ConfigMapInformer;
use endpoints_informer::EndpointsInformer;
use id_mgr::IdMgr;
use local_ip_address::list_afinet_netifas;
use local_ip_address::local_ip;
use node_informer::NodeInformer;
use pod_informer::PodInformer;
use qlib::kernel::TSC;
use qlib::linux_def::*;
use qlib::socket_buf::{SocketBuff, SocketBuffIntern};
use qlib::unix_socket::UnixSocket;
use rdma_agent::*;
use rdma_channel::RDMAChannel;
use rdma_conn::*;
use rdma_ctrlconn::Node;
use rdma_ctrlconn::Pod;
use service_informer::ServiceInformer;
use spin::Mutex;
use std::io::Error;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::{env, mem, ptr, thread, time};

use std::net::UdpSocket;
use std::str;

use std::os::unix::net::UnixStream;
use unix_socket_def::*;

pub static GLOBAL_ALLOCATOR: HostAllocator = HostAllocator::New();

lazy_static! {
    pub static ref GLOBAL_LOCK: Mutex<()> = Mutex::new(());
}

#[allow(unused_macros)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}
#[cfg(offload = "yes")]
#[repr(C)]
// #[repr(packed)]
#[derive(Default, Copy, Clone, Debug)]
pub struct EpollEvent {
    pub Events: u32,
    pub U64: u64,
}

#[cfg(not(offload = "yes"))]
#[repr(C)]
#[repr(packed)]
#[derive(Default, Copy, Clone, Debug)]
pub struct EpollEvent {
    pub Events: u32,
    pub U64: u64,
}

//const READ_FLAGS: i32 = libc::EPOLLIN; //libc::EPOLLET | libc::EPOLLIN;
const READ_FLAGS: i32 = libc::EPOLLET | libc::EPOLLIN;
//const READ_FLAGS: i32 = LibcConst::EPOLLET as i32 | libc::EPOLLIN;

//const READ_FLAGS: i32 = libc::EPOLLONESHOT | libc::EPOLLIN | libc::EPOLLOUT;
const WRITE_FLAGS: i32 = libc::EPOLLET | libc::EPOLLOUT;
//const WRITE_FLAGS: i32 = libc::EPOLLONESHOT | libc::EPOLLIN | libc::EPOLLOUT;

const READ_WRITE_FLAGS: i32 = libc::EPOLLET | libc::EPOLLOUT | libc::EPOLLIN;

pub const IO_WAIT_CYCLES: i64 = 100_000_000; // 1ms

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RDMA Service is starting!");
    #[cfg(offload = "yes")]{
        RDMA.Init("mlx5_2", 1);
    }
    #[cfg(not(offload = "yes"))]{
        RDMA.Init("rocep152s0f0", 1);
    }
    let hostname_os = hostname::get()?;
    match hostname_os.into_string() {
        Ok(v) => RDMA_CTLINFO.hostname_set(v),
        Err(_) => println!("Failed to retrieve hostname."),
    }
    println!("Hostname is {}", RDMA_CTLINFO.hostname_get());

    let epoll_fd = epoll_create().expect("can create epoll queue");
    println!("epoll_fd is {}", epoll_fd);
    RDMA_CTLINFO.epoll_fd_set(epoll_fd);

    let args: Vec<_> = env::args().collect();
    let server_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    println!("server_fd is {}", server_fd);
    unblock_fd(server_fd);
    RDMA_CTLINFO.fds_insert(server_fd, Srv_FdType::TCPSocketServer);
    epoll_add(epoll_fd, server_fd, read_write_event(server_fd as u64))?;

    if RDMA_CTLINFO.isK8s {
        tokio::spawn(async {
            while !RDMA_CTLINFO.isCMConnected_get() {
                let mut node_informer = NodeInformer::new();
                match node_informer.run().await {
                    Err(e) => {
                        println!("Error to handle nodes: {:?}", e);
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
            let mut pod_informer = PodInformer::new();
            match pod_informer.run().await {
                Err(e) => {
                    println!("Error to handle pods: {:?}", e);
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

        tokio::spawn(async {
            while !RDMA_CTLINFO.isCMConnected_get() {
                thread::sleep_ms(1000);
            }
            let mut endpoints_informer = EndpointsInformer::new();
            match endpoints_informer.run().await {
                Err(e) => {
                    println!("Error to handle endpointses: {:?}", e);
                }
                Ok(_) => (),
            };
        });

        tokio::spawn(async {
            while !RDMA_CTLINFO.isCMConnected_get() {
                thread::sleep_ms(1000);
            }
            let mut configmap_informer = ConfigMapInformer::new();
            match configmap_informer.run().await {
                Err(e) => {
                    println!("Error to handle configmaps: {:?}", e);
                }
                Ok(_) => (),
            };
        });
    }

    //watch RDMA event
    let ccFd = RDMA.CompleteChannelFd();
    println!("RDMA CCFd: {}", ccFd);
    RDMA_CTLINFO.fds_insert(ccFd, Srv_FdType::RDMACompletionChannel);
    //let ret1 = unsafe { rdmaffi::ibv_req_notify_cq(RDMA.CompleteQueue(), 0) };
    //println!("ret1: {}", ret1);

    unblock_fd(ccFd);
    epoll_add(epoll_fd, ccFd, read_write_event(ccFd as u64))?;

    //RDMA.HandleCQEvent();
    //TOBEDELETE
    // println!("before create memfd");
    // let memfd = unsafe {
    //     libc::memfd_create(
    //         "Server memfd".as_ptr() as *const i8,
    //         libc::MFD_ALLOW_SEALING,
    //     )
    // };
    // println!("memfd: {}", memfd);
    // if memfd == -1 {
    //     panic!(
    //         "fail to create memfd, error is: {}",
    //         std::io::Error::last_os_error()
    //     );
    // }

    unsafe {
        let serv_addr: libc::sockaddr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 8888u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([0, 0, 0, 0]).to_be(),
            },
            sin_zero: mem::zeroed(),
        };

        let mut enable = 1;
        let _res = libc::setsockopt(
            server_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &mut enable as *mut _ as *mut libc::c_void,
            4,
        );

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

        if !RDMA_CTLINFO.isK8s {
            if args.len() > 1 {
                // let peerIpAddr = u32::from(Ipv4Addr::from_str("172.16.1.43").unwrap()).to_be();
                // let localIpAddr = u32::from(Ipv4Addr::from_str("172.16.1.99").unwrap()).to_be();
                let peerIpAddr;
                let localIpAddr;
                #[cfg(offload = "yes")]{
                    peerIpAddr = u32::from(Ipv4Addr::from_str("192.168.2.21").unwrap()).to_be();
                    localIpAddr = u32::from(Ipv4Addr::from_str("192.168.2.23").unwrap()).to_be();
                }
                #[cfg(not(offload = "yes"))]{
                    peerIpAddr = u32::from(Ipv4Addr::from_str("192.168.2.1").unwrap()).to_be();
                    localIpAddr = u32::from(Ipv4Addr::from_str("192.168.2.3").unwrap()).to_be();
                }
                
                RDMA_CTLINFO.localIp_set(localIpAddr);
                SetupConnection(&peerIpAddr);
                SetupConnection(&localIpAddr);

                // serv_addr = libc::sockaddr_in {
                //     sin_family: libc::AF_INET as u16,
                //     sin_port: 8889u16.to_be(),
                //     sin_addr: libc::in_addr {
                //         s_addr: u32::from_be_bytes([0, 0, 0, 0]).to_be(),
                //     },
                //     sin_zero: mem::zeroed(),
                // };
            } else {
                let localIpAddr;
                #[cfg(offload = "yes")]{
                    localIpAddr = u32::from(Ipv4Addr::from_str("192.168.2.23").unwrap()).to_be();
                }
                #[cfg(not(offload = "yes"))]{
                    localIpAddr = u32::from(Ipv4Addr::from_str("192.168.2.3").unwrap()).to_be();
                }
                RDMA_CTLINFO.localIp_set(localIpAddr);
                SetupConnection(&localIpAddr);
            }
        }
    }
    println!("litener sock fd is {}", server_fd);

    // unix domain socket

    let mut unix_sock_path = "/var/quarkrdma/rdma_srv_socket";
    if args.len() > 1 {
        unix_sock_path = args.get(1).unwrap(); //"/tmp/rdma_srv1";
    }
    println!("unix_sock_path: {}", unix_sock_path);
    if Path::new(unix_sock_path).exists() {
        println!("Deleting existing socket file: {}", unix_sock_path);
        fs::remove_file(unix_sock_path).expect("File delete failed");
    }

    let srv_unix_sock = UnixSocket::NewServer(unix_sock_path).unwrap();
    let srv_unix_sock_fd = srv_unix_sock.as_raw_fd();
    RDMA_CTLINFO.fds_insert(
        srv_unix_sock_fd,
        Srv_FdType::UnixDomainSocketServer(srv_unix_sock),
    );

    println!("srv_unix_sock: {}", srv_unix_sock_fd);
    unblock_fd(srv_unix_sock_fd);

    epoll_add(
        epoll_fd,
        srv_unix_sock_fd,
        read_event(srv_unix_sock_fd as u64),
    )?;

    //TOBEDELETE
    // println!("before create memfd");
    // let memfd = unsafe {
    //     libc::memfd_create(
    //         "Server memfd".as_ptr() as *const i8,
    //         libc::MFD_ALLOW_SEALING,
    //     )
    // };
    // println!("memfd: {}", memfd);
    // if memfd == -1 {
    //     panic!(
    //         "fail to create memfd, error is: {}",
    //         std::io::Error::last_os_error()
    //     );
    // }

    // let cur_timestamp = RDMA_CTLINFO.nodes.lock().get(&local_ip).unwrap().timestamp;
    // println!("timestamp is {}", cur_timestamp);

    // let mut eventdata: u64 = 0;
    let srvEventFd;
    #[cfg(offload = "yes")]{
        srvEventFd =  gen_eventfd();
    }
    #[cfg(not(offload = "yes"))]{
        srvEventFd = RDMA_SRV.eventfd;
    }
    println!("srvEventFd: {}", srvEventFd);
    epoll_add(epoll_fd, srvEventFd, read_event(srvEventFd as u64))?;
    unblock_fd(srvEventFd);
    RDMA_CTLINFO.fds_insert(srvEventFd, Srv_FdType::SrvEventFd(srvEventFd));
    let hostname = RDMA_CTLINFO.hostname_get();
    let mut events: Vec<EpollEvent> = Vec::with_capacity(1024);


    //Add UDP socket for client-to-service ctrl commnunication
    let srv_udp_sock = unsafe {libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)};
    unsafe{
        let udp_s_addr;
        #[cfg(offload = "yes")]{
            udp_s_addr = u32::from_be_bytes([192, 168, 2, 23]).to_be();
        }
        #[cfg(not(offload = "yes"))]{
            udp_s_addr = u32::from_be_bytes([192, 168, 2, 3]).to_be();
        }
        let srv_udp_addr: libc::sockaddr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 3340u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: udp_s_addr,
            },
            sin_zero: mem::zeroed(),
        };
        let result = libc::bind(
            srv_udp_sock,
            &srv_udp_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of_val(&srv_udp_addr) as u32,
        );
        if result < 0 {
            libc::close(srv_udp_sock);
            panic!("last OS error: {:?}", Error::last_os_error());
        }
    }
    println!("srv_udp_sock: {}", srv_udp_sock);
    epoll_add(epoll_fd, srv_udp_sock, read_event(srv_udp_sock as u64))?;
    unblock_fd(srv_udp_sock);
    RDMA_CTLINFO.fds_insert(
        srv_udp_sock,
        Srv_FdType::UDPCtrlSocketServer,
    );
  
    loop {
        events.clear();
        // println!("in loop");
        // let ret = unsafe {
        //     libc::read(
        //         RDMA_SRV.eventfd,
        //         &mut eventdata as *mut _ as *mut libc::c_void,
        //         8,
        //     )
        // };

        // println!("read eventfd, ret: {}", ret);

        // // if ret < 0 {
        // //     println!("error: {}", errno::errno().0);
        // // }

        // if ret < 0 && errno::errno().0 != SysErr::EAGAIN {
        //     panic!(
        //         "Service Wakeup fail... eventfd is {}, errno is {}",
        //         RDMA_SRV.eventfd,
        //         errno::errno().0
        //     );
        // }

        RDMA_SRV.shareRegion.srvBitmap.store(1, Ordering::Release);
        // RDMA.HandleCQEvent().unwrap();
        // RDMAProcessOnce(&mut HashMap::new());
        RDMAProcessOnce();
        // println!("Before sleep");
        let res = match syscall!(epoll_wait(
            epoll_fd,
            events.as_mut_ptr() as *mut libc::epoll_event,
            1024,
            -1 as libc::c_int
        )) {
            Ok(v) => v,
            Err(e) => panic!("error during epoll wait: {}", e),
        };

        unsafe { events.set_len(res as usize) };
        RDMA_SRV.shareRegion.srvBitmap.store(0, Ordering::Release);
        HandleEvents(epoll_fd, &events, &hostname)?;
        RDMAProcess(epoll_fd, &hostname);
    }
}

fn HandleEvents(epoll_fd: i32, events: &Vec<EpollEvent>, hostname: &String) -> Result<(), Box<dyn std::error::Error>> {
    let mut eventdata: u64 = 0;
    for ev in events {
        // print!("u64: {:x}, events: {:x}", {ev.U64}, {ev.Events});
        // let event_data = RDMA_CTLINFO.fds_get(ev.U64 as i32);
        let mut fds = RDMA_CTLINFO.fds.lock();
        let event_data = fds.get(&(ev.U64 as i32)).unwrap();
        match event_data {
            Srv_FdType::TCPSocketServer => {
                // println!("TCPSocketServer");
                let stream_fd;
                let mut cliaddr: libc::sockaddr_in = unsafe { mem::zeroed() };
                let mut len = mem::size_of_val(&cliaddr) as u32;
                unsafe {
                    stream_fd = libc::accept(
                        ev.U64 as i32,
                        &mut cliaddr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                        &mut len,
                    );
                }
                unblock_fd(stream_fd);
                println!("stream_fd is: {}", stream_fd);

                let peerIpAddrU32 = cliaddr.sin_addr.s_addr;

                let controlRegionId =
                    RDMA_SRV.controlBufIdMgr.lock().AllocId().unwrap() as usize; // TODO: should handle no space issue.
                let sockBuf = SocketBuff(Arc::new(SocketBuffIntern::InitWithShareMemory(
                    MemoryDef::DEFAULT_BUF_PAGE_COUNT,
                    &RDMA_SRV.controlRegion.ioMetas[controlRegionId].readBufAtoms as *const _
                        as u64,
                    &RDMA_SRV.controlRegion.ioMetas[controlRegionId].writeBufAtoms as *const _
                        as u64,
                    &RDMA_SRV.controlRegion.ioMetas[controlRegionId].consumeReadData as *const _
                        as u64,
                    &RDMA_SRV.controlRegion.iobufs[controlRegionId].read as *const _ as u64,
                    &RDMA_SRV.controlRegion.iobufs[controlRegionId].write as *const _ as u64,
                    true,
                )));

                let rdmaConn = RDMAConn::New(
                    stream_fd,
                    sockBuf.clone(),
                    RDMA_SRV.keys[controlRegionId / 1024][1],
                    RDMA_SRV.udpQP.qpNum(),
                );
                let rdmaChannel = RDMAChannel::New(
                    0,
                    RDMA_SRV.keys[controlRegionId / 1024][0],
                    RDMA_SRV.keys[controlRegionId / 1024][1],
                    sockBuf.clone(),
                    rdmaConn.clone(),
                );
                let rdmaControlChannel =
                    RDMAControlChannel::New((*rdmaChannel.clone()).clone());

                match rdmaConn.ctrlChan.lock().chan.upgrade() {
                    None => {
                        println!("ctrlChann is null")
                    }
                    _ => {
                        println!("ctrlChann is not null")
                    }
                }
                //*rdmaConn.ctrlChan.lock() = RDMAControlChannel::New((*rdmaControlChannel.clone()).clone());
                *rdmaConn.ctrlChan.lock() = rdmaControlChannel.clone();
                match rdmaConn.ctrlChan.lock().chan.upgrade() {
                    None => {
                        println!("ctrlChann is null")
                    }
                    _ => {
                        println!("ctrlChann is not null")
                    }
                }
                for qp in rdmaConn.GetQueuePairs() {
                    RDMA_SRV
                        .controlChannels
                        .lock()
                        .insert(qp.qpNum(), rdmaControlChannel.clone());
                    RDMA_SRV
                        .controlChannels2
                        .lock()
                        .insert(qp.qpNum(), rdmaChannel.clone());
                }

                if peerIpAddrU32 == RDMA_CTLINFO.localIp_get() {
                    RDMA_SRV.conns.lock().insert(0, rdmaConn);
                    fds.insert(stream_fd, Srv_FdType::TCPSocketConnect(0));
                } else {
                    RDMA_SRV.conns.lock().insert(peerIpAddrU32, rdmaConn);
                    fds.insert(stream_fd, Srv_FdType::TCPSocketConnect(peerIpAddrU32));
                }

                epoll_add(epoll_fd, stream_fd, read_write_event(stream_fd as u64))?;
            }
            Srv_FdType::TCPSocketConnect(ipAddr) => match RDMA_SRV.conns.lock().get(&ipAddr) {
                Some(rdmaConn) => {
                    // println!("TCPSocketConnect, ipAddr: {}", ipAddr);
                    rdmaConn.Notify(ev.Events as u64);
                }
                _ => {
                    panic!("no RDMA connection for {} found!", ipAddr)
                }
            },
            Srv_FdType::UnixDomainSocketServer(_srv_sock) => {
                // println!("UnixDomainSocketServer");
                let conn_sock = UnixSocket::Accept(ev.U64 as i32).unwrap();
                let conn_sock_fd = conn_sock.as_raw_fd();
                unblock_fd(conn_sock_fd);
                // RDMA_CTLINFO.fds_insert(conn_sock_fd, Srv_FdType::UnixDomainSocketConnect(conn_sock));
                fds.insert(conn_sock_fd, Srv_FdType::UnixDomainSocketConnect(conn_sock));
                epoll_add(epoll_fd, conn_sock_fd, read_event(conn_sock_fd as u64))?;
                println!("add unix sock fd: {}", conn_sock_fd);
            }
            Srv_FdType::UnixDomainSocketConnect(conn_sock) => {
                // println!("UnixDomainSocketConnect");
                loop {
                    let mut body = [0u8; 64];
                    // let ptr = &mut body as *mut _ as *mut u8;
                    // let buf = unsafe { slice::from_raw_parts_mut(ptr, 4) };
                    let buf = body.as_mut_slice();
                    let ret = conn_sock.ReadWithFds(buf);
                    match ret {
                        Ok((size, _fds)) => {
                            debug!("UnixDomainSocketConnect, size: {}", size);
                            if size == 0 {
                                debug!("Disconnect from client");
                                let agentIdOption = RDMA_SRV
                                    .sockToAgentIds
                                    .lock()
                                    .remove(&conn_sock.as_raw_fd());
                                match agentIdOption {
                                    Some(agentId) => {
                                        debug!("Remove agent from RDMA_SRV.agents");
                                        RDMA_SRV.agents.lock().remove(&agentId);
                                        fds.remove(&(ev.U64 as i32));
                                    }
                                    None => {
                                        error!(
                                            "AgentId not found for sockfd: {}",
                                            conn_sock.as_raw_fd()
                                        )
                                    }
                                }
                                break;
                            } else {
                                // let clientRole = ClientRole::Parse(body);
                                // init
                                println!("init!!");
                                InitContainer(&conn_sock, body);
                            }
                        }
                        Err(e) => {
                            println!("Error to read fds: {:?}", e);
                            break;
                        }
                    }
                }
            }
            Srv_FdType::RDMACompletionChannel => {
                // println!("Got RDMA completion event");
                // let _cnt = RDMA.PollCompletionQueueAndProcess();
                // RDMAProcess();
                RDMA.HandleCQEvent().unwrap();
                // RDMAProcessOnce();
                // println!("FdType::RDMACompletionChannel, processed {} wcs", cnt);

                // let mut i = 0;
                // let sec = time::Duration::from_secs(1);

                // loop {
                //     let cnt = RDMAProcessOnce();
                //     println!("Got RDMA completion event 3.1, cnt {}", cnt);
                //     i += 1;
                //     if i == 10 || cnt != 0 {
                //         break;
                //     }
                //     thread::sleep(sec);
                //     println!("Got RDMA completion event 3.2, sleep {} seconds", i);
                // }
                // println!("Got RDMA completion event 4");
            }
            Srv_FdType::SrvEventFd(srvEventFd) => {
                println!("Got SrvEventFd event {}", srvEventFd);
                // print!("u64: {}, events: {:x}", ev.U64, ev.Events);
                // println!("srvEvent notified ****************1");
                // RDMAProcess();
                let ret = unsafe {
                    libc::read(
                        *srvEventFd,
                        &mut eventdata as *mut _ as *mut libc::c_void,
                        16,
                    )
                };

                if ret < 0 {
                    println!("error: {}", errno::errno().0);
                }

                if ret < 0 && errno::errno().0 != SysErr::EAGAIN {
                    panic!(
                        "Service Wakeup fail... eventfd is {}, errno is {}",
                        srvEventFd,
                        errno::errno().0
                    );
                }
                // println!("eventdata: {}", eventdata);
                // RDMA_SRV.HandleClientRequest();
            }
            Srv_FdType::NodeEventFd(nodeEvent) => {
                // println!("Got NodeEvent: {:?}", nodeEvent);
                let node = RDMA_CTLINFO.node_get(nodeEvent.ip);
                if node.hostname.eq_ignore_ascii_case(&hostname) {
                    RDMA_CTLINFO.timestamp_set(node.timestamp);
                    RDMA_CTLINFO.localIp_set(node.ipAddr);
                }
                std::mem::drop(fds);
                SetupConnections();
            }
            Srv_FdType::UDPCtrlSocketServer =>{
                // Receives a single datagram message on the socket. 
                let mut buf = [0u8; 64];
                let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
                let mut addrlen = std::mem::size_of_val(&addr) as libc::socklen_t;

                let bytes_received = unsafe {
                    libc::recvfrom(
                        ev.U64 as i32,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                        &mut addr as *mut _ as *mut libc::sockaddr,
                        &mut addrlen,
                    )
                };
                if bytes_received > 1024 {
                    println!("Receive data len {}", bytes_received);
                    continue; 
                }
                let data = &buf[..bytes_received as usize];
                let data_str = str::from_utf8(data).unwrap();
                println!("Received data: {}", data_str);
                InitContainer_Offload(ev.U64 as i32, buf, addr, addrlen)
            }
        }
        //println!("Finish processing fd: {}, event: {}", ev.U64, ev.Events);
    }
    Ok(())
}

fn RDMAProcess(epoll_fd: i32, hostname: &String) {
    let mut start = TSC.Rdtsc();
    let mut events: Vec<EpollEvent> = Vec::with_capacity(1024);
    // let mut channels: HashMap<u32, HashSet<u32>> = HashMap::new();
    loop {
        // let count = RDMAProcessOnce(&mut channels);
        events.clear();
        let mut totalCount = 0;
        loop {
            let currentCount = RDMAProcessOnce();
            totalCount += currentCount;
            // 1000 can be tuned further based on perf data
            if currentCount == 0 || totalCount > 1000 {
                break;
            }
        }
        
        // let res = 0;
        let res = match syscall!(epoll_wait(
            epoll_fd,
            events.as_mut_ptr() as *mut libc::epoll_event,
            1024,
            0 as libc::c_int,
        )) {
            Ok(v) => v,
            Err(e) => panic!("error during epoll wait: {}", e),
        };
        unsafe { events.set_len(res as usize) };
        // println!("RDMAProcess, res: {}, events len: {}, len2: {}", res, events.len(), &events.len());
        let _ = HandleEvents(epoll_fd, &events, hostname);
        if totalCount > 0 || res > 0{
            start = TSC.Rdtsc();
        }
        if TSC.Rdtsc() - start >= (IO_WAIT_CYCLES/100) {
            break;
        }
        // if count == 0 {
        //     break;
        // }
    }
    // if channels.len() != 0 {
    //     debug!("RDMAProcess, channels: {}", channels.len());
    // }
    // SendConsumedData(&mut channels);
}

// fn RDMAProcessOnce(channels: &mut HashMap<u32, HashSet<u32>>) -> usize {
fn RDMAProcessOnce() -> usize {
    let mut count = 0;
    let mut channels: HashMap<u32, HashSet<u32>> = HashMap::new();
    count += RDMA.PollCompletionQueueAndProcess(&mut channels);
    // debug!("RDMAProcessOnce, channels: {:?}", channels);
    if channels.len() > 1 {
        debug!("RDMAProcessOnce, channels: {}", channels.len());
    }
    // SendConsumedData(&mut channels);
    count += RDMA_SRV.HandleClientRequest();
    count
}

fn SendConsumedData(channels: &mut HashMap<u32, HashSet<u32>>) {
    for (k, v) in channels.into_iter() {
        RDMA_SRV
            .controlChannels
            .lock()
            .get(k)
            .unwrap()
            .SendConsumeDataGroup(v);
    }
}

fn InitContainer(conn_sock: &UnixSocket, podId: [u8; 64]) {
    let cliEventFd = unsafe { libc::eventfd(0, 0) };
    unblock_fd(cliEventFd);

    let rdmaAgentId = RDMA_SRV.agentIdMgr.lock().AllocId().unwrap();
    let rdmaAgent = RDMAAgent::New(
        rdmaAgentId,
        String::new(),
        conn_sock.as_raw_fd(),
        cliEventFd,
        podId,
    );
    RDMA_SRV
        .agents
        .lock()
        .insert(rdmaAgentId, rdmaAgent.clone());
    RDMA_SRV
        .podIdToAgents
        .lock()
        .insert(rdmaAgent.podId, rdmaAgent.clone());
    match RDMA_CTLINFO
        .podIdToVpcIpAddr
        .lock()
        .get(&String::from_utf8(rdmaAgent.podId.to_vec()).unwrap())
    {
        Some(vpcIpAddr) => {
            *rdmaAgent.ipAddr.lock() = vpcIpAddr.ipAddr;
            *rdmaAgent.vpcId.lock() = vpcIpAddr.vpcId;
            RDMA_SRV
                .vpcIpAddrToAgents
                .lock()
                .insert(*vpcIpAddr, rdmaAgent.clone());
        }
        None => {}
    }

    RDMA_SRV
        .sockToAgentIds
        .lock()
        .insert(conn_sock.as_raw_fd(), rdmaAgentId);
    let body = [123, rdmaAgentId];
    let ptr = &body as *const _ as *const u8;
    let buf = unsafe { slice::from_raw_parts(ptr, 8) };
    conn_sock
        .WriteWithFds(
            buf,
            &[
                RDMA_SRV.eventfd,
                RDMA_SRV.srvMemfd,
                cliEventFd,
                rdmaAgent.client_memfd,
            ],
        )
        .unwrap();
}

fn InitContainer_Offload(ctrl_sock: i32, podId: [u8; 64], addr: libc::sockaddr, addrlen: libc::socklen_t) {
    let cliEventFd = unsafe { libc::eventfd(0, 0) };
    unblock_fd(cliEventFd);

    let rdmaAgentId = RDMA_SRV.agentIdMgr.lock().AllocId().unwrap();

    //For offloading case, we set bit of agent as 1 forever;
    let l2idx =  rdmaAgentId as usize / 64;
    let l2pos =  rdmaAgentId as usize % 64;
    let l1idx = l2idx / 64;
    let l1pos = l2idx % 64;
    RDMA_SRV.shareRegion.bitmap.l2bitmap[l2idx].fetch_or(1 << l2pos, Ordering::SeqCst);
    RDMA_SRV.shareRegion.bitmap.l1bitmap[l1idx].fetch_or(1 << l1pos, Ordering::SeqCst);
   
    let rdmaAgent = RDMAAgent::New(
        rdmaAgentId,
        String::new(),
        ctrl_sock,
        cliEventFd,
        podId,
    );
    RDMA_SRV
        .agents
        .lock()
        .insert(rdmaAgentId, rdmaAgent.clone());
    RDMA_SRV
        .podIdToAgents
        .lock()
        .insert(rdmaAgent.podId, rdmaAgent.clone());
    match RDMA_CTLINFO
        .podIdToVpcIpAddr
        .lock()
        .get(&String::from_utf8(rdmaAgent.podId.to_vec()).unwrap())
    {
        Some(vpcIpAddr) => {
            *rdmaAgent.ipAddr.lock() = vpcIpAddr.ipAddr;
            *rdmaAgent.vpcId.lock() = vpcIpAddr.vpcId;
            RDMA_SRV
                .vpcIpAddrToAgents
                .lock()
                .insert(*vpcIpAddr, rdmaAgent.clone());
        }
        None => {}
    }

    RDMA_SRV
        .sockToAgentIds
        .lock()
        .insert(ctrl_sock, rdmaAgentId);
    let body = [123, rdmaAgentId];
    let ptr = body.as_ptr() as *const u8;
    let buf = unsafe { slice::from_raw_parts(ptr, 8) };

    println!("srvMemRegion addr {:?}", RDMA_SRV.srvMemRegion.addr as usize);
    println!("rdmaAgent shareMemRegion {:?}", rdmaAgent.shareMemRegion.addr);

    // Send back with udp ctrl socket
    // let mut buf = [123, rdmaAgentId];
    // buf[0..4].copy_from_slice(&rdmaAgentId.to_le_bytes());
    unsafe{
        let res = libc::sendto(ctrl_sock,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
               0,
               &addr as *const _ as *mut libc::sockaddr,
               addrlen);
        println!("Send {} back to {}", rdmaAgentId, res);
    }

}


fn SetupConnections() {
    let timestamp = RDMA_CTLINFO.timestamp_get();
    if timestamp == 0 {
        return;
    }

    let node_ips_set = RDMA_CTLINFO.get_node_ips_for_connecting();
    for ip in node_ips_set.iter() {
        if !RDMA_SRV.ExistsConnection(ip) {
            SetupConnection(ip);
        }
    }
}

fn SetupConnection(ip: &u32) {
    let node = RDMA_CTLINFO.node_get(*ip);
    let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    unblock_fd(sock_fd);
    RDMA_CTLINFO.fds_insert(sock_fd, Srv_FdType::TCPSocketConnect(node.ipAddr));
    let epoll_fd = RDMA_CTLINFO.epoll_fd_get();
    match epoll_add(epoll_fd, sock_fd, read_write_event(sock_fd as u64)) {
        Err(e) => {
            println!("epoll_add failed: {:?}", e);
        }
        _ => {
            println!("epoll_add succeed, fd: {}", sock_fd);
        }
    }

    println!("new conn");
    let controlRegionId = RDMA_SRV.controlBufIdMgr.lock().AllocId().unwrap() as usize; // TODO: should handle no space issue.
    let sockBuf = SocketBuff(Arc::new(SocketBuffIntern::InitWithShareMemory(
        MemoryDef::DEFAULT_BUF_PAGE_COUNT,
        &RDMA_SRV.controlRegion.ioMetas[controlRegionId].readBufAtoms as *const _ as u64,
        &RDMA_SRV.controlRegion.ioMetas[controlRegionId].writeBufAtoms as *const _ as u64,
        &RDMA_SRV.controlRegion.ioMetas[controlRegionId].consumeReadData as *const _ as u64,
        &RDMA_SRV.controlRegion.iobufs[controlRegionId].read as *const _ as u64,
        &RDMA_SRV.controlRegion.iobufs[controlRegionId].write as *const _ as u64,
        true,
    )));

    let rdmaConn = RDMAConn::New(
        sock_fd,
        sockBuf.clone(),
        RDMA_SRV.keys[controlRegionId / 16][1],
        RDMA_SRV.udpQP.qpNum(),
    );
    let rdmaChannel = RDMAChannel::New(
        0,
        RDMA_SRV.keys[controlRegionId / 16][0],
        RDMA_SRV.keys[controlRegionId / 16][1],
        sockBuf.clone(),
        rdmaConn.clone(),
    );

    let rdmaControlChannel = RDMAControlChannel::New((*rdmaChannel.clone()).clone());
    match rdmaConn.ctrlChan.lock().chan.upgrade() {
        None => {
            println!("ctrlChann is null")
        }
        _ => {
            println!("ctrlChann is not null")
        }
    }

    //*rdmaConn.ctrlChan.lock() = RDMAControlChannel::New((*rdmaControlChannel.clone()).clone());
    *rdmaConn.ctrlChan.lock() = rdmaControlChannel.clone();
    match rdmaConn.ctrlChan.lock().chan.upgrade() {
        None => {
            println!("ctrlChann is null")
        }
        _ => {
            println!("ctrlChann is not null")
        }
    }
    for qp in rdmaConn.GetQueuePairs() {
        RDMA_SRV
            .controlChannels
            .lock()
            .insert(qp.qpNum(), rdmaControlChannel.clone());
        RDMA_SRV
            .controlChannels2
            .lock()
            .insert(qp.qpNum(), rdmaChannel.clone());
    }

    RDMA_SRV.conns.lock().insert(node.ipAddr, rdmaConn.clone());
    unsafe {
        let serv_addr: libc::sockaddr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 8888u16.to_be(), //8888 is the port for RDMASvc to shake hands
            sin_addr: libc::in_addr {
                s_addr: node.ipAddr,
            },
            sin_zero: mem::zeroed(),
        };
        let ret = libc::connect(
            sock_fd,
            &serv_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of_val(&serv_addr) as u32,
        );

        println!("ret is {}, error: {}", ret, Error::last_os_error());
    }
}


fn gen_eventfd() -> RawFd {

    let efd = unsafe { libc::eventfd(0, 0) };

    let client_sendfd_sock_fd = UnixSocket::NewClient("/EVENTFDSOCKET").unwrap();
    let client_sendfd_sock = UnixSocket { fd: client_sendfd_sock_fd };
    let res = client_sendfd_sock.SendFd(efd.as_raw_fd());
    drop(client_sendfd_sock);
    efd
}