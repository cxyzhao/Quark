
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
#[cfg(with_doca = "yes")]
use super::qlib::doca::sample_common::hex_dump;
#[cfg(with_doca = "yes")]
use super::qlib::doca::doca_common_util;
#[cfg(with_doca = "yes")]
use super::qlib::doca::dma_copy_core::*;
use std::ffi::{CStr, CString};


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

    pub fn initialize(cliSock: i32, localShareAddr: u64, globalShareAddr: u64, podId:[u8; 64]) -> Self {
       
        #[cfg(with_doca = "yes")]{


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
            unsafe{
                //rdma_srv's udp port is 3340 
                let srv_udp_addr: libc::sockaddr_in =  libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: 3340u16.to_be(),
                    sin_addr: libc::in_addr {
                        //192.168.2.23
                        s_addr: u32::from_be_bytes([192, 168, 2, 23]).to_be(),
                    },
                    sin_zero: mem::zeroed(),
                };
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




            /* Create client MemFd
                While offloading RDMASrv to BF2,
                MemFd is created on host-side.
            */
            let cli_memfd_name = CString::new("RDMASrvMemFdonHost").expect("CString::new failed for RDMASrvMemFd");
            let cli_memfd = unsafe { libc::memfd_create(cli_memfd_name.as_ptr(), libc::MFD_ALLOW_SEALING) };
            if cli_memfd == -1 {
                panic!(
                    "fail to create cli_memfd, error is: {}",
                    std::io::Error::last_os_error()
                );
            }
            let cli_size = mem::size_of::<ClientShareRegion>();
            println!("ClientShareRegion size is {}", cli_size);
            let _ret = unsafe { libc::ftruncate(cli_memfd, cli_size as i64) };


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

         




            // Create a buffer of bytes to be dumped
            let data: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05];

            // Call the hex_dump function to get a string representation of the buffer
            let c_str = unsafe { CStr::from_ptr(hex_dump(data.as_ptr() as *const libc::c_void, data.len())) };
            // Convert the C string to a Rust string
            let rust_str = c_str.to_str().expect("failed to convert C string to Rust str");
            println!("Hex dump: {}", rust_str);

            let mut dma_core_state = core_state {
                dev: std::ptr::null_mut(),
                mmap: std::ptr::null_mut(),
                buf_inv: std::ptr::null_mut(),
                ctx: std::ptr::null_mut(),
                dma_ctx: std::ptr::null_mut(),
                workq: std::ptr::null_mut(),
            };

            
            let host_pci: &str = "98:00.0";
            let mut host_pci_array: [::std::os::raw::c_char; 8] = [0; 8];
            for (i, c) in host_pci.chars().enumerate() {
                host_pci_array[i] = c as ::std::os::raw::c_char;
            }

            let file_path_str: &str = "/home/cxyzhao/host-quark/Quark/dma_test_file.txt";
            let mut file_path_array: [::std::os::raw::c_char; 128] = [0; 128];
            for (i, c) in file_path_str.chars().enumerate() {
                file_path_array[i] = c as ::std::os::raw::c_char;
            }

            let mut dma_cfg = dma_copy_cfg {
                mode: dma_copy_mode_DMA_COPY_MODE_HOST,
                file_path: file_path_array,
                //For Host side
                cc_dev_pci_addr:  host_pci_array,
                cc_dev_rep_pci_addr: [0; 8],
                is_file_found_locally: true,
                //This is file_size of dma_test_file
                file_size: 1024
            };


            let mut ep = doca_comm_channel_ep_t::new();
            let mut ep_addr : *mut doca_comm_channel_ep_t = &mut ep as *mut doca_comm_channel_ep_t;
            let mut cc_dev = doca_dev::new();
            let mut cc_dev_addr : *mut doca_dev = &mut cc_dev as *mut doca_dev;
            let mut cc_dev_rep = doca_dev_rep::new();
            let mut cc_dev_rep_addr : *mut doca_dev_rep = &mut cc_dev_rep as *mut doca_dev_rep;
            let mut peer_addr = doca_comm_channel_addr_t::new();
            let mut peer_addr_addr : *mut doca_comm_channel_addr_t = &mut peer_addr as *mut doca_comm_channel_addr_t;


            /* Init Comm Channel */
            let mut result = unsafe{init_cc(&mut dma_cfg, &mut ep_addr, &mut cc_dev_addr, &mut cc_dev_rep_addr)};
            // Check the return value of the function
            if result != doca_error_DOCA_SUCCESS {
                println!("Failed to initiate Comm Channel");
            } else {
                println!("Successfully initiate Comm Channel");
            }

            /* Open DOCA dma device */
            result = unsafe { open_dma_device(&mut dma_core_state.dev) };
            // Check the return value of the function
            if result != doca_error_DOCA_SUCCESS {
                println!("Failed to open DMA device");
            } else {
                println!("Successfully opened DMA device");
            }
            
            /* Create DOCA core objects */
            result = unsafe {create_core_objs(&mut dma_core_state,  dma_cfg.mode)};
            // Check the return value of the function
            if result != doca_error_DOCA_SUCCESS {
                println!("Failed to create DOCA core structures");
            } else {
                println!("Successfully  create DOCA core structures");
            }

            /* Init DOCA core objects */
            result = unsafe{init_core_objs(&mut dma_core_state, &mut dma_cfg)};
            if result != doca_error_DOCA_SUCCESS {
                println!("Failed to initialize DOCA core structures");
            } else {
                println!("Successfully initialize DOCA core structures");
            }

            /* DMA_COPY_MODE_HOST */
            result = unsafe{host_start_dma_copy(&mut dma_cfg, &mut dma_core_state, ep_addr, &mut peer_addr_addr)};
            if result != doca_error_DOCA_SUCCESS {
                println!("Failed to start host dma copy");
            } else {
                println!("Successfully start host dma copy");
            }
  
            let cli_sock = UnixSocket { fd: cliSock };
            let rdmaSvcCli = RDMASvcClient::New(
                0,
                srv_memfd,
                0,
                cli_memfd,
                0,
                cli_sock,
                localShareAddr,
                globalShareAddr,
                podId,
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