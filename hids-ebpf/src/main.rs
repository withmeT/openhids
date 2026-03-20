#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::map,
    macros::uretprobe,
    maps::RingBuf,
    programs::RetProbeContext,
    helpers::bpf_probe_read_user_str_bytes,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm},
};

use hids_common::{CommandEvent, COMM_LEN, MAX_LINE};

#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[uretprobe]
pub fn uretprobe_readline(ctx: RetProbeContext) -> u32 {
    match unsafe { try_readline(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_readline(ctx: RetProbeContext) -> Result<(), i64> {
    let ret: *const u8 = ctx.ret();
    if ret.is_null() {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xffff_ffff) as u32;

    let mut comm = [0u8; COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        comm = c;
    }

    // Reserve ringbuf space and fill in-place to stay under BPF stack limits.
    let mut entry = match unsafe { EVENTS.reserve::<CommandEvent>(0) } {
        Some(e) => e,
        None => return Ok(()),
    };

    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = pid;
        (*ev).tgid = tgid;
        (*ev).uid = uid;

        core::ptr::copy_nonoverlapping(comm.as_ptr(), (*ev).comm.as_mut_ptr(), COMM_LEN);

        let line_buf = core::slice::from_raw_parts_mut((*ev).line.as_mut_ptr(), MAX_LINE);
        let len = match bpf_probe_read_user_str_bytes(ret as *const u8, line_buf) {
            Ok(b) => b.len(),
            Err(e) => {
                entry.discard(0);
                return Err(e);
            }
        };
        if len == 0 {
            entry.discard(0);
            return Ok(());
        }
        (*ev).len = len as u32;
    }

    entry.submit(0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
