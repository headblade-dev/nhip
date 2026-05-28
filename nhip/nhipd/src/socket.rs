use tokio::io::unix::AsyncFd;
use std::os::fd::{AsRawFd, RawFd};
use anyhow::Result;

pub struct RawSocket {
    pub async_fd: AsyncFd<RawFd>,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        *self.async_fd.get_ref()
    }
}

impl RawSocket {
    pub fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET, 
                libc::SOCK_RAW | libc::SOCK_NONBLOCK, 
                libc::ETH_P_ALL.to_be())
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // binding
        if let Err(e) = Self::bind_to_all_ifaces(fd) {
            log::error!("Failed to bind socket to interfaces: {}", e);
            return Err(anyhow::anyhow!("Failed to bind socket to interfaces"));
        }

        // buffers
        if let Err(e) = Self::set_buffer_size(fd, 16) {
            log::error!("Failed to set buffer size: {}", e);
            return Err(anyhow::anyhow!("Failed to set buffer size"));
        }
        
        // async wrapping
        let async_fd = AsyncFd::new(fd);

        if let Err(e) = async_fd {
            log::error!("Failed to assign AsyncFd: {}", e);
            return Err(e.into());
        }
        let async_fd = async_fd?;

        Ok(Self { async_fd })
    }

    pub fn bind_to_all_ifaces (fd: RawFd) -> Result<()> {
        unsafe {
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            sll.sll_ifindex = 0; // all ifaces

            let ret = libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(err.into())
            }
        }

        Ok(())
    }
    
    pub fn set_buffer_size(fd: RawFd, size_mb: u8) -> Result<()> {
        let buf_size: libc::c_int = 1024 * 1024 * size_mb as libc::c_int; // 16 MB of buffer

        unsafe {
            libc::setsockopt( // for receive
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt( // for send
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        Ok(())
    }

    pub async fn send(&self, ifindex: u32, data: &[u8]) -> Result<()> {
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8]
        };

        let mut guard = self.async_fd.writable().await?;
        let fd = *guard.get_inner();

        let ret = unsafe {
            libc::sendto(
                fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                log::warn!("NHIP Daemon: TX buffer full, packet dropped on ifindex {}", ifindex);
                return Ok(());
            }
            return Err(err.into());
        }
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, u32)> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            let fd = *guard.get_inner();

            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut addrlen: libc::socklen_t = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

            let ret = unsafe {
                libc::recvfrom(
                    fd, 
                    buf.as_mut_ptr() as *mut libc::c_void, 
                    buf.len(), 
                    0,
                    &mut sll as *mut _ as *mut libc::sockaddr,
                    &mut addrlen as *mut libc::socklen_t                    
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(err.into());
            }

            return Ok((ret as usize, sll.sll_ifindex as u32));
        }
    }
}
