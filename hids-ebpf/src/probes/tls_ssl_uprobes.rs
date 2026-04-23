use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_buf,
    },
    macros::{uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext},
};

use hids_common::{COMM_LEN, TLS_DATA_MAX, TlsEvent, TlsFdKey};

use crate::maps::{TLS_EVENTS, TLS_READ_ARGS, TLS_READ_SSLPTR, TLS_SSL_FD};

const DIR_SSL_WRITE: u8 = 0;
const DIR_SSL_READ: u8 = 1;

#[uprobe]
pub fn uprobe_ssl_write(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_write(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[uprobe]
pub fn uprobe_ssl_read_enter(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_read_enter(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[uretprobe]
pub fn uretprobe_ssl_read(ctx: RetProbeContext) -> u32 {
    match unsafe { try_ssl_read(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[uprobe]
pub fn uprobe_ssl_set_fd(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_set_fd(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[uprobe]
pub fn uprobe_ssl_set_rfd(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_set_fd(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[uprobe]
pub fn uprobe_ssl_set_wfd(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_set_fd(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[uprobe]
pub fn uprobe_ssl_free(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_free(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn fill_event_common(ev: *mut TlsEvent, ssl_ptr: u64, direction: u8) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = (uid_gid & 0xffff_ffff) as u32;

    (*ev).pid = pid;
    (*ev).tgid = tgid;
    (*ev).uid = uid;
    (*ev).ssl_ptr = ssl_ptr;
    let fd_key = TlsFdKey { tgid, ssl_ptr };
    (*ev).fd = match unsafe { TLS_SSL_FD.get(&fd_key) } {
        Some(fd) => *fd,
        None => -1,
    };
    (*ev).direction = direction;
    (*ev).len = 0;
    (*ev).data = [0u8; TLS_DATA_MAX];

    let mut comm = [0u8; COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        comm = c;
    }
    core::ptr::copy_nonoverlapping(comm.as_ptr(), (*ev).comm.as_mut_ptr(), COMM_LEN);
}

unsafe fn try_ssl_write(ctx: ProbeContext) -> Result<(), i64> {
    let ssl_ptr = ctx.arg::<u64>(0).ok_or(0i64)?;
    let buf_ptr = ctx.arg::<*const u8>(1).ok_or(0i64)?;
    let num = ctx.arg::<i32>(2).ok_or(0i64)?;
    if buf_ptr.is_null() || num <= 0 {
        return Ok(());
    }

    let read_len = core::cmp::min(num as usize, TLS_DATA_MAX);
    let mut entry = match unsafe { TLS_EVENTS.reserve::<TlsEvent>(0) } {
        Some(e) => e,
        None => return Ok(()),
    };
    let ev = entry.as_mut_ptr();
    unsafe { fill_event_common(ev, ssl_ptr, DIR_SSL_WRITE) };
    unsafe {
        if let Err(e) = bpf_probe_read_user_buf(buf_ptr, &mut (&mut (*ev).data)[..read_len]) {
            entry.discard(0);
            return Err(e as i64);
        }
        (*ev).len = read_len as u32;
    }
    entry.submit(0);
    Ok(())
}

unsafe fn try_ssl_set_fd(ctx: ProbeContext) -> Result<(), i64> {
    let ssl_ptr = ctx.arg::<u64>(0).ok_or(0i64)?;
    let fd = ctx.arg::<i32>(1).ok_or(0i64)?;
    if ssl_ptr == 0 || fd < 0 {
        return Ok(());
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let key = TlsFdKey { tgid, ssl_ptr };
    let _ = unsafe { TLS_SSL_FD.insert(&key, &fd, 0) };
    Ok(())
}

unsafe fn try_ssl_free(ctx: ProbeContext) -> Result<(), i64> {
    let ssl_ptr = ctx.arg::<u64>(0).ok_or(0i64)?;
    if ssl_ptr == 0 {
        return Ok(());
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let key = TlsFdKey { tgid, ssl_ptr };
    let _ = unsafe { TLS_SSL_FD.remove(&key) };
    Ok(())
}

unsafe fn try_ssl_read_enter(ctx: ProbeContext) -> Result<(), i64> {
    let ssl_ptr = ctx.arg::<u64>(0).ok_or(0i64)?;
    let buf_ptr = ctx.arg::<*const u8>(1).ok_or(0i64)?;
    if buf_ptr.is_null() {
        return Ok(());
    }
    let key = bpf_get_current_pid_tgid();
    let val = buf_ptr as u64;
    let _ = unsafe { TLS_READ_ARGS.insert(&key, &val, 0) };
    let _ = unsafe { TLS_READ_SSLPTR.insert(&key, &ssl_ptr, 0) };
    Ok(())
}

unsafe fn try_ssl_read(ctx: RetProbeContext) -> Result<(), i64> {
    let ret = ctx.ret::<i32>();
    if ret <= 0 {
        return Ok(());
    }
    let key = bpf_get_current_pid_tgid();
    let buf_ptr = match unsafe { TLS_READ_ARGS.get_ptr(&key) } {
        Some(p) => unsafe { *p as *const u8 },
        None => return Ok(()),
    };
    let _ = unsafe { TLS_READ_ARGS.remove(&key) };
    let ssl_ptr = match unsafe { TLS_READ_SSLPTR.get_ptr(&key) } {
        Some(p) => unsafe { *p },
        None => 0,
    };
    let _ = unsafe { TLS_READ_SSLPTR.remove(&key) };

    let read_len = core::cmp::min(ret as usize, TLS_DATA_MAX);
    let mut entry = match unsafe { TLS_EVENTS.reserve::<TlsEvent>(0) } {
        Some(e) => e,
        None => return Ok(()),
    };
    let ev = entry.as_mut_ptr();
    unsafe { fill_event_common(ev, ssl_ptr, DIR_SSL_READ) };
    unsafe {
        if let Err(e) = bpf_probe_read_user_buf(buf_ptr, &mut (&mut (*ev).data)[..read_len]) {
            entry.discard(0);
            return Err(e as i64);
        }
        (*ev).len = read_len as u32;
    }
    entry.submit(0);
    Ok(())
}
