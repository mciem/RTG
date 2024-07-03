use std::mem;
use std::io;
use std::os::raw::c_void;
use winapi::um::winnt::PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;
use winapi::shared::wtypesbase::ULONG;

const PROCESS_SIGNATURE_POLICY_MITIGATION: i32 = 8;

extern "system" {
    fn SetProcessMitigationPolicy(
        Policy: ULONG,
        lpBuffer: *const c_void,
        dwLength: ULONG,
    ) -> i32;
}

fn set_process_mitigation_policy(policy: i32, lp_buffer: *const c_void, size: ULONG) -> Result<(), io::Error> {
    unsafe {
        let ret = SetProcessMitigationPolicy(policy as ULONG, lp_buffer, size);
        if ret == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn anti_injection() {
    let only_microsoft_binaries: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = unsafe { mem::zeroed() };
    only_microsoft_binaries.MicrosoftSignedOnly();

    let lp_buffer: *const c_void = &only_microsoft_binaries as *const _ as *const c_void;
    let size = mem::size_of::<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY>() as ULONG;

    match set_process_mitigation_policy(PROCESS_SIGNATURE_POLICY_MITIGATION, lp_buffer, size) {
        Ok(()) => { },
        Err(_) => { },
    }
}