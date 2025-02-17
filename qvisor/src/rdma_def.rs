
use alloc::collections::BTreeMap;
use alloc::slice;
use alloc::sync::Arc;
use spin::Mutex;
use std::{mem, ptr};
use std::io::Error;
use core::sync::atomic::AtomicU32;

use super::qlib::linux_def::*;
use super::qlib::rdma_share::*;
use super::qlib::rdma_svc_cli::*;
use super::qlib::unix_socket::UnixSocket;
use super::qlib::idallocator::IdAllocator;
use super::vmspace::VMSpace;
use super::unix_socket_def::*;
use std::ffi::{CStr, CString};
use libc::{shm_open, mmap, ftruncate, c_char, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_FAILED, O_RDWR};
use std::os::unix::io::{AsRawFd, RawFd};

impl Drop for RDMASvcClient {
    fn drop(&mut self) {
        error!("RDMASvcClient::Drop");
    }
}

impl RDMASvcClient {
    fn New(
        srvEventFd: i32,
        srvMemFd: i32,
        cliEventFd: i32,
        cliMemFd: i32,
        agentId: u32,
        cliSock: UnixSocket,
        localShareAddr: u64,
        globalShareAddr: u64,
        podId: [u8; 64],
    ) -> Self {
        let cliShareSize = mem::size_of::<ClientShareRegion>();
        // debug!("RDMASvcClient::New, cli size: {:x}", cliShareSize);
        // debug!("RDMASvcClient::New, srv size: {:x}", mem::size_of::<ShareRegion>());
        // debug!("RDMASvcClient::New, ioBuffer: {:x}", mem::size_of::<IOBuf>());
        // debug!("RDMASvcClient::New, IOMetas: {:x}", mem::size_of::<IOMetas>());
        // debug!("RDMASvcClient::New, RingQueue<RDMAResp>: {:x}", mem::size_of::<RingQueue<RDMAResp>>());
        // debug!("RDMASvcClient::New, RingQueue<RDMAResp>: {:x}", mem::size_of::<RingQueue<RDMAReq>>());
        // debug!("RDMASvcClient::New, RDMAResp: {:x}", mem::size_of::<RDMAResp>());
        // debug!("RDMASvcClient::New, RDMAReq: {:x}", mem::size_of::<RDMAReq>());

        let cliShareAddr = unsafe {
            libc::mmap(
                if localShareAddr == 0 {
                    ptr::null_mut()
                } else {
                    localShareAddr as *mut libc::c_void
                },
                cliShareSize,
                libc::PROT_READ | libc::PROT_WRITE,
                if localShareAddr == 0 {
                    libc::MAP_SHARED
                } else {
                    libc::MAP_SHARED | libc::MAP_FIXED
                },
                cliMemFd,
                0,
            )
        };
        assert!(cliShareAddr as u64 == localShareAddr || localShareAddr == 0);

        let cliShareRegion = unsafe { &mut (*(cliShareAddr as *mut ClientShareRegion)) };
        let udpBufferAllocator = UDPBufferAllocator::New(
            &cliShareRegion.udpBufSent as *const _ as u64,
            UDP_RECV_PACKET_COUNT as u32,
        );
        let cliShareRegion = Mutex::new(cliShareRegion);

        let srvShareSize = mem::size_of::<ShareRegion>();
        let srvShareAddr = unsafe {
            libc::mmap(
                if globalShareAddr == 0 {
                    ptr::null_mut()
                } else {
                    globalShareAddr as *mut libc::c_void
                },
                srvShareSize,
                libc::PROT_READ | libc::PROT_WRITE,
                if globalShareAddr == 0 {
                    libc::MAP_SHARED
                } else {
                    libc::MAP_SHARED | libc::MAP_FIXED
                },
                srvMemFd,
                0,
            )
        };
        assert!(srvShareAddr as u64 == globalShareAddr || globalShareAddr == 0);

        let srvShareRegion = unsafe { &mut (*(srvShareAddr as *mut ShareRegion)) };
        let srvShareRegion = Mutex::new(srvShareRegion);
        RDMASvcClient {
            intern: Arc::new(RDMASvcCliIntern {
                agentId,
                cliSock,
                cliMemFd,
                srvMemFd,
                srvEventFd,
                cliEventFd,
                cliMemRegion: MemRegion {
                    addr: cliShareAddr as u64,
                    len: cliShareSize as u64,
                },
                cliShareRegion,
                srvMemRegion: MemRegion {
                    addr: srvShareAddr as u64,
                    len: srvShareSize as u64,
                },
                srvShareRegion,
                channelToSocketMappings: Mutex::new(BTreeMap::new()),
                rdmaIdToSocketMappings: Mutex::new(BTreeMap::new()),
                nextRDMAId: AtomicU32::new(0),
                podId,
                udpSentBufferAllocator: Mutex::new(udpBufferAllocator),
                portToFdInfoMappings: Mutex::new(BTreeMap::new()),

                //refer to: https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables
                //"The default values are 32768 and 60999 respectively."
                tcpPortAllocator: Mutex::new(IdAllocator::New(32768, 28232)), // 60999 - 32768 + 1 = 28231 + 1 = 28232
                udpPortAllocator: Mutex::new(IdAllocator::New(32768, 28232)), // 60999 - 32768 + 1 = 28231 + 1 = 28232
                // timestamp: Mutex::new(Vec::with_capacity(16)),
            }),
        }
    }

    /*
    Overload New function
    Here, mmap is done before New is invoked, so cliShareAddr and srvShareAddr are parameter.
    The purpose of this New functions is to save one round trip communcation of cli-agent for 
    offloading case
    */
    fn New_WithMemAddr(
        srvEventFd: i32,
        srvMemFd: i32,
        cliEventFd: i32,
        cliMemFd: i32,
        agentId: u32,
        cliSock: UnixSocket,
        localShareAddr: u64,
        globalShareAddr: u64,
        podId: [u8; 64],
        cliShareAddr: *mut libc::c_void,
        srvShareAddr: *mut libc::c_void,
    ) -> Self {
        let cliShareSize = mem::size_of::<ClientShareRegion>();
        // debug!("RDMASvcClient::New, cli size: {:x}", cliShareSize);
        // debug!("RDMASvcClient::New, srv size: {:x}", mem::size_of::<ShareRegion>());
        // debug!("RDMASvcClient::New, ioBuffer: {:x}", mem::size_of::<IOBuf>());
        // debug!("RDMASvcClient::New, IOMetas: {:x}", mem::size_of::<IOMetas>());
        // debug!("RDMASvcClient::New, RingQueue<RDMAResp>: {:x}", mem::size_of::<RingQueue<RDMAResp>>());
        // debug!("RDMASvcClient::New, RingQueue<RDMAResp>: {:x}", mem::size_of::<RingQueue<RDMAReq>>());
        // debug!("RDMASvcClient::New, RDMAResp: {:x}", mem::size_of::<RDMAResp>());
        // debug!("RDMASvcClient::New, RDMAReq: {:x}", mem::size_of::<RDMAReq>());

        // let cliShareAddr = unsafe {
        //     libc::mmap(
        //         if localShareAddr == 0 {
        //             ptr::null_mut()
        //         } else {
        //             localShareAddr as *mut libc::c_void
        //         },
        //         cliShareSize,
        //         libc::PROT_READ | libc::PROT_WRITE,
        //         if localShareAddr == 0 {
        //             libc::MAP_SHARED
        //         } else {
        //             libc::MAP_SHARED | libc::MAP_FIXED
        //         },
        //         cliMemFd,
        //         0,
        //     )
        // };

        assert!(cliShareAddr as u64 == localShareAddr || localShareAddr == 0);

        let cliShareRegion = unsafe { &mut (*(cliShareAddr as *mut ClientShareRegion)) };
        let udpBufferAllocator = UDPBufferAllocator::New(
            &cliShareRegion.udpBufSent as *const _ as u64,
            UDP_RECV_PACKET_COUNT as u32,
        );
        let cliShareRegion = Mutex::new(cliShareRegion);

        let srvShareSize = mem::size_of::<ShareRegion>();
        // let srvShareAddr = unsafe {
        //     libc::mmap(
        //         if globalShareAddr == 0 {
        //             ptr::null_mut()
        //         } else {
        //             globalShareAddr as *mut libc::c_void
        //         },
        //         srvShareSize,
        //         libc::PROT_READ | libc::PROT_WRITE,
        //         if globalShareAddr == 0 {
        //             libc::MAP_SHARED
        //         } else {
        //             libc::MAP_SHARED | libc::MAP_FIXED
        //         },
        //         srvMemFd,
        //         0,
        //     )
        // };
        assert!(srvShareAddr as u64 == globalShareAddr || globalShareAddr == 0);

        let srvShareRegion = unsafe { &mut (*(srvShareAddr as *mut ShareRegion)) };
        let srvShareRegion = Mutex::new(srvShareRegion);
        RDMASvcClient {
            intern: Arc::new(RDMASvcCliIntern {
                agentId,
                cliSock,
                cliMemFd,
                srvMemFd,
                srvEventFd,
                cliEventFd,
                cliMemRegion: MemRegion {
                    addr: cliShareAddr as u64,
                    len: cliShareSize as u64,
                },
                cliShareRegion,
                srvMemRegion: MemRegion {
                    addr: srvShareAddr as u64,
                    len: srvShareSize as u64,
                },
                srvShareRegion,
                channelToSocketMappings: Mutex::new(BTreeMap::new()),
                rdmaIdToSocketMappings: Mutex::new(BTreeMap::new()),
                nextRDMAId: AtomicU32::new(0),
                podId,
                udpSentBufferAllocator: Mutex::new(udpBufferAllocator),
                portToFdInfoMappings: Mutex::new(BTreeMap::new()),

                //refer to: https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables
                //"The default values are 32768 and 60999 respectively."
                tcpPortAllocator: Mutex::new(IdAllocator::New(32768, 28232)), // 60999 - 32768 + 1 = 28231 + 1 = 28232
                udpPortAllocator: Mutex::new(IdAllocator::New(32768, 28232)), // 60999 - 32768 + 1 = 28231 + 1 = 28232
                // timestamp: Mutex::new(Vec::with_capacity(16)),
            }),
        }
    }

    // pub fn init(path: &str) -> RDMASvcClient {
    //     let cli_sock = UnixSocket::NewClient(path).unwrap();

    //     let body = 1;
    //     let ptr = &body as *const _ as *const u8;
    //     let buf = unsafe { slice::from_raw_parts(ptr, 4) };
    //     cli_sock.WriteWithFds(buf, &[]).unwrap();

    //     let mut body = [0, 0];
    //     let ptr = &mut body as *mut _ as *mut u8;
    //     let buf = unsafe { slice::from_raw_parts_mut(ptr, 8) };
    //     let (size, fds) = cli_sock.ReadWithFds(buf).unwrap();
    //     if body[0] == 123 {
    //         println!("size: {}, fds: {:?}, agentId: {}", size, fds, body[1]);
    //     }

    //     let rdmaSvcCli = RDMASvcClient::New(fds[0], fds[1], fds[2], fds[3], body[1], cli_sock);
    //     rdmaSvcCli
    // }

    fn gen_eventfd() -> RawFd {

        let efd = unsafe { libc::eventfd(0, 0) };
    
        let client_sendfd_sock_fd = UnixSocket::NewClient("/EVENTFDSOCKET").unwrap();
        let client_sendfd_sock = UnixSocket { fd: client_sendfd_sock_fd };
        let res = client_sendfd_sock.SendFd(efd.as_raw_fd());
        drop(client_sendfd_sock);
        efd
    }

    pub fn initialize(cliSock: i32, localShareAddr: u64, globalShareAddr: u64, podId:[u8; 64]) -> Self {
       
        #[cfg(offload = "yes")]{
            /*
            UDP control section
            */
            let buf = podId.as_slice();
            //create and bind client udp socket
            let cli_udp_sock = unsafe {libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)};
            unsafe{
                let cli_udp_addr: libc::sockaddr_in = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: 3340u16.to_be(),
                    sin_addr: libc::in_addr {
                        //192.168.2.3
                        s_addr: u32::from_be_bytes([192, 168, 2, 3]).to_be(),
                    },
                    sin_zero: mem::zeroed(),
                };
                let result = libc::bind(
                    cli_udp_sock,
                    &cli_udp_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of_val(&cli_udp_addr) as u32,
                );
                if result < 0 {
                    libc::close(cli_udp_sock);
                    panic!("last OS error: {:?}", Error::last_os_error());
                }
            }
            //agent_id is data_agent_id[1]
            let mut data_agent_id= [0, 0];
            //rdma_srv's udp port is 3340 
            let srv_udp_addr: libc::sockaddr_in =  unsafe{ 
                libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 3340u16.to_be(),
                sin_addr: libc::in_addr {
                    //192.168.2.23
                    s_addr: u32::from_be_bytes([192, 168, 2, 23]).to_be(),
                },
                sin_zero: mem::zeroed(),
                }
            };
            //send pod id
            unsafe{
                let mut addrlen = std::mem::size_of_val(&srv_udp_addr) as libc::socklen_t;
                let result = libc::sendto(cli_udp_sock,
                    buf as *const _  as *mut libc::c_void,
                    buf.len(),
                    0,
                    &srv_udp_addr as *const _ as *mut libc::sockaddr,
                    addrlen);
                println!("Send to rdma_srv {}", result);
                if result < 0 {
                    libc::close(cli_udp_sock);
                    panic!("last OS error: {:?}", Error::last_os_error());
                }
            }

            //receive agent id
            unsafe{
                let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
                let mut addrlen = std::mem::size_of_val(&addr) as libc::socklen_t;
                let bytes_received =  unsafe {
                    libc::recvfrom(
                        cli_udp_sock,
                        data_agent_id.as_mut_ptr() as *mut libc::c_void,
                        data_agent_id.len() *  std::mem::size_of::<u32>(),
                        0,
                        &mut addr as *mut _ as *mut libc::sockaddr,
                        &mut addrlen,
                    )
                };
                if bytes_received < 0 {
                    libc::close(cli_udp_sock);
                    panic!("last OS error: {:?}", Error::last_os_error());
                }
                println!("{} bytes_received, Received agent id: {}", bytes_received, data_agent_id[1]);
            }


            /* Create client MemFd
                While offloading RDMASrv to BF2,
                MemFd is created on host-side.
            */

            // let cli_memfd_name = CString::new("RDMASrvMemFdonHost").expect("CString::new failed for RDMASrvMemFd");
            // let cli_memfd = unsafe { libc::memfd_create(cli_memfd_name.as_ptr(), libc::MFD_ALLOW_SEALING) };

            //get cli_memfd from broker process
            const cli_memfd_name : *const c_char = b"/SharedMemRegionWithBroker\0".as_ptr() as *const c_char;
            let cli_memfd = unsafe { shm_open(cli_memfd_name, O_RDWR, libc::S_IRUSR | libc::S_IWUSR) };

            if cli_memfd == -1 {
                panic!(
                    "fail to create cli_memfd, error is: {}",
                    std::io::Error::last_os_error()
                );
            }
            let cli_size = mem::size_of::<ClientShareRegion>();
            println!("ClientShareRegion size is {}", cli_size);
            let mut _ret = unsafe { libc::ftruncate(cli_memfd, cli_size as i64) };
            


            let cliShareSize = mem::size_of::<ClientShareRegion>();
            let cliShareAddr = unsafe {
                libc::mmap(
                    if localShareAddr == 0 {
                        ptr::null_mut()
                    } else {
                        localShareAddr as *mut libc::c_void
                    },
                    cliShareSize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    if localShareAddr == 0 {
                        libc::MAP_SHARED
                    } else {
                        libc::MAP_SHARED | libc::MAP_FIXED
                    },
                    cli_memfd,
                    0,
                )
            };

            //For offloading, the region needs to be initialized by both the host and the client. 
            //In the case of non-offloading, only the server is responsible for initialization.
            let mut cliAddr = cliShareAddr as *mut ClientShareRegion;
            unsafe {
                let cliAddr_ref = &*cliAddr;
                cliAddr_ref.sq.Init();
                cliAddr_ref.cq.Init();
            }
            

            /* srv memory region memfd
                While offloading RDMASrv to BF2,
                MemFd is created on host-side.
            */
            let srv_memfd_name = CString::new("RDMASrvMemFd").expect("CString::new failed for RDMASrvMemFd");
            let srv_memfd = unsafe { libc::memfd_create(srv_memfd_name.as_ptr(), libc::MFD_ALLOW_SEALING) };
            // println!("memfd::{}", memfd);
            if srv_memfd == -1 {
                panic!(
                    "fail to create srv_memfd, error is: {}",
                    std::io::Error::last_os_error()
                );
            }
            let srv_size = mem::size_of::<ShareRegion>();
            _ret = unsafe { libc::ftruncate(srv_memfd, srv_size as i64) };

            let srvShareSize = mem::size_of::<ShareRegion>();
            let srvShareAddr = unsafe {
                libc::mmap(
                    if globalShareAddr == 0 {
                        ptr::null_mut()
                    } else {
                        globalShareAddr as *mut libc::c_void
                    },
                    srvShareSize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    if globalShareAddr == 0 {
                        libc::MAP_SHARED
                    } else {
                        libc::MAP_SHARED | libc::MAP_FIXED
                    },
                    srv_memfd,
                    0,
                )
            };
            
            println!("cliShareAddr {:?} {}", cliShareAddr as usize, std::mem::size_of::<*mut libc::c_void>());
            println!("srvShareAddr {:?} {}", srvShareAddr as usize, std::mem::size_of::<*mut libc::c_void>());
            
            
            /* srveventfd / clieventfd
                While offloading RDMASrv to BF2,
                MemFd is created on host-side.
            */
            //TODO(trigger broker eventfd)
            let srveventfd  = unsafe { libc::eventfd(0, 0) };
            VMSpace::UnblockFd(srveventfd);
            let clieventfd;
            // let clieventfd  = unsafe { libc::eventfd(0, 0) };
            clieventfd = unsafe { Self::gen_eventfd() };
            VMSpace::UnblockFd(clieventfd);

            let cli_sock = UnixSocket { fd: cliSock };
            let rdmaSvcCli = RDMASvcClient::New_WithMemAddr(
                srveventfd,
                srv_memfd,
                clieventfd,
                cli_memfd,
                data_agent_id[1],
                cli_sock,
                localShareAddr,
                globalShareAddr,
                podId,
                cliShareAddr,
                srvShareAddr
            );

            return rdmaSvcCli;
        }
        #[cfg(not(offload = "yes"))]{
            // let cli_sock = UnixSocket::NewClient(path).unwrap();
            let cli_sock = UnixSocket { fd: cliSock };

            // let body = 1;
            // let ptr = &body as *const _ as *const u8;
            // let buf = unsafe { slice::from_raw_parts(ptr, 4) };
            let buf = podId.as_slice();
            cli_sock.WriteWithFds(buf, &[]).unwrap();

            let mut body = [0, 0];
            let ptr = &mut body as *mut _ as *mut u8;
            let buf = unsafe { slice::from_raw_parts_mut(ptr, 8) };
            let (_size, fds) = cli_sock.ReadWithFds(buf).unwrap();
            let rdmaSvcCli = RDMASvcClient::New(
                fds[0],
                fds[1],
                fds[2],
                fds[3],
                body[1],
                cli_sock,
                localShareAddr,
                globalShareAddr,
                podId,
            );
            rdmaSvcCli
        }
    }

    pub fn wakeupSvc(&self) {
        let data = 16u64;
        let ret = unsafe {
            libc::write(
                self.srvEventFd,
                &data as *const _ as *const libc::c_void,
                mem::size_of_val(&data) as usize,
            )
        };
        // println!("ret: {}", ret);
        if ret < 0 {
            println!("error: {}", std::io::Error::last_os_error());
        }
    }

    pub fn CreateSocket(&self) -> i64 {
        VMSpace::Socket(AFType::AF_INET, 1, 0)
    }
}