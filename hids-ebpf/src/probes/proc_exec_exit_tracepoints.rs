use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::tracepoint,
    programs::TracePointContext,
};

use hids_common::{COMM_LEN, ExecEvent, ExitEvent};

use crate::maps::{EXEC_EVENTS, EXIT_EVENTS};

fn get_pid_tgid() -> (u32, u32) {
    // pid_tgid: lower 32 bits pid, upper 32 bits tgid
    let v = bpf_get_current_pid_tgid();
    let pid = (v & 0xffff_ffff) as u32;
    let tgid = (v >> 32) as u32;
    (pid, tgid)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_enter_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_execve(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_enter_execve(_ctx: TracePointContext) -> Result<(), i64> {
    let (pid, tgid) = get_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xffff_ffff) as u32;

    let mut comm = [0u8; COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        comm = c;
    }

    let mut entry = match unsafe { EXEC_EVENTS.reserve::<ExecEvent>(0) } {
        Some(e) => e,
        None => return Ok(()),
    };

    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = pid;
        (*ev).tgid = tgid;
        (*ev).uid = uid;
        core::ptr::copy_nonoverlapping(comm.as_ptr(), (*ev).comm.as_mut_ptr(), COMM_LEN);
    }

    entry.submit(0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_exit")]
pub fn trace_enter_exit(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_exit(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_exit_group")]
pub fn trace_enter_exit_group(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_exit(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_enter_exit(ctx: TracePointContext) -> Result<(), i64> {
    // sys_enter_exit(_group) format:
    //  - common_pid at offset 4
    //  - __syscall_nr at offset 12
    //  - error_code at offset 16 (8 bytes)
    //
    // We treat `error_code` as the exit code.
    let exit_code_u64: u64 = unsafe { ctx.read_at::<u64>(16) }?;
    let exit_code = exit_code_u64 as i32;

    let (pid, tgid) = get_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xffff_ffff) as u32;
    let mut comm = [0u8; COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        comm = c;
    }

    let mut entry = match unsafe { EXIT_EVENTS.reserve::<ExitEvent>(0) } {
        Some(e) => e,
        None => return Ok(()),
    };
    let ev = entry.as_mut_ptr();

    unsafe {
        (*ev).pid = pid;
        (*ev).tgid = tgid;
        (*ev).uid = uid;
        core::ptr::copy_nonoverlapping(comm.as_ptr(), (*ev).comm.as_mut_ptr(), COMM_LEN);
        (*ev).exit_code = exit_code;
    }

    entry.submit(0);
    Ok(())
}

