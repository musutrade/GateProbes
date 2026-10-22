//! Connect via the held O_PATH inode, never by reopening its ambient pathname.
use crate::Result;
use gatehouse_runtime_protocol::lifecycle_v2::protected_context::ProtectedContext;
use std::{
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};
pub(crate) struct SocketIdentity<'a> {
    context: &'a ProtectedContext,
    path: PathBuf,
    uid: u32,
}
impl<'a> SocketIdentity<'a> {
    pub fn verify(context: &'a ProtectedContext) -> Result<Self> {
        let fd = context.socket_file()?.as_raw_fd();
        let uid = context.snapshot()?.0.observation.socket.uid;
        Ok(Self {
            context,
            path: PathBuf::from(format!("/proc/self/fd/{fd}")),
            uid,
        })
    }
    pub fn revalidate(&self) -> Result<()> {
        self.context.revalidate()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn check_peer(&self, fd: i32) -> Result<()> {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut size,
            )
        };
        if rc != 0
            || size as usize != std::mem::size_of_val(&peer)
            || peer.uid != self.uid
            || peer.pid <= 0
        {
            return Err("native Unix peer uid rejected");
        }
        self.revalidate()
    }
}
