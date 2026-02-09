mod chacha;
mod packet;
mod salamander;

use libc::{c_char, c_int, size_t};
use std::ffi::CString;
use std::ptr;

#[repr(C)]
pub struct Buffer {
    pub ptr: *mut u8,
    pub len: size_t,
}

impl Buffer {
    fn from_vec(mut v: Vec<u8>) -> Buffer {
        let out = Buffer {
            ptr: v.as_mut_ptr(),
            len: v.len(),
        };
        std::mem::forget(v);
        out
    }

    fn empty() -> Buffer {
        Buffer {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn sl_free_buffer(buf: Buffer) {
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(buf.ptr, buf.len, buf.len);
    }
}

#[no_mangle]
pub extern "C" fn sl_last_error_free(err: *mut c_char) {
    if err.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(err);
    }
}

fn set_err(err_out: *mut *mut c_char, msg: String) {
    if err_out.is_null() {
        return;
    }
    if let Ok(c) = CString::new(msg) {
        unsafe {
            *err_out = c.into_raw();
        }
    }
}

#[no_mangle]
pub extern "C" fn sl_xchacha_encrypt(
    key: *const u8,
    key_len: size_t,
    nonce: *const u8,
    nonce_len: size_t,
    plaintext: *const u8,
    plaintext_len: size_t,
    aad: *const u8,
    aad_len: size_t,
    err_out: *mut *mut c_char,
) -> Buffer {
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    let nonce = unsafe { std::slice::from_raw_parts(nonce, nonce_len) };
    let plaintext = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let aad = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };

    match chacha::xchacha_encrypt(key, nonce, plaintext, aad) {
        Ok(v) => Buffer::from_vec(v),
        Err(e) => {
            set_err(err_out, e);
            Buffer::empty()
        }
    }
}

#[no_mangle]
pub extern "C" fn sl_xchacha_decrypt(
    key: *const u8,
    key_len: size_t,
    nonce: *const u8,
    nonce_len: size_t,
    ciphertext: *const u8,
    ciphertext_len: size_t,
    aad: *const u8,
    aad_len: size_t,
    err_out: *mut *mut c_char,
) -> Buffer {
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    let nonce = unsafe { std::slice::from_raw_parts(nonce, nonce_len) };
    let ciphertext = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let aad = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };

    match chacha::xchacha_decrypt(key, nonce, ciphertext, aad) {
        Ok(v) => Buffer::from_vec(v),
        Err(e) => {
            set_err(err_out, e);
            Buffer::empty()
        }
    }
}

#[no_mangle]
pub extern "C" fn sl_salamander_xor(
    input: *const u8,
    input_len: size_t,
    key: *const u8,
    key_len: size_t,
    nonce: u64,
    err_out: *mut *mut c_char,
) -> Buffer {
    let input = unsafe { std::slice::from_raw_parts(input, input_len) };
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };

    match salamander::salamander_xor(input, key, nonce) {
        Ok(v) => Buffer::from_vec(v),
        Err(e) => {
            set_err(err_out, e);
            Buffer::empty()
        }
    }
}

#[no_mangle]
pub extern "C" fn sl_build_packet(
    version: u8,
    flags: u8,
    flow_id: u32,
    seq: u32,
    payload: *const u8,
    payload_len: size_t,
    err_out: *mut *mut c_char,
) -> Buffer {
    let payload = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let header = packet::RawPacketHeader {
        version,
        flags,
        flow_id,
        seq,
        payload_len: payload.len() as u16,
    };

    match packet::build_packet(&header, payload) {
        Ok(v) => Buffer::from_vec(v),
        Err(e) => {
            set_err(err_out, e);
            Buffer::empty()
        }
    }
}

#[no_mangle]
pub extern "C" fn sl_parse_packet_header(
    input: *const u8,
    input_len: size_t,
    version_out: *mut u8,
    flags_out: *mut u8,
    flow_id_out: *mut u32,
    seq_out: *mut u32,
    payload_offset_out: *mut u32,
    payload_len_out: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    let input = unsafe { std::slice::from_raw_parts(input, input_len) };

    match packet::parse_packet(input) {
        Ok((h, _)) => {
            unsafe {
                if !version_out.is_null() {
                    *version_out = h.version;
                }
                if !flags_out.is_null() {
                    *flags_out = h.flags;
                }
                if !flow_id_out.is_null() {
                    *flow_id_out = h.flow_id;
                }
                if !seq_out.is_null() {
                    *seq_out = h.seq;
                }
                if !payload_offset_out.is_null() {
                    *payload_offset_out = packet::HEADER_LEN as u32;
                }
                if !payload_len_out.is_null() {
                    *payload_len_out = h.payload_len as u32;
                }
            }
            0
        }
        Err(e) => {
            set_err(err_out, e);
            -1
        }
    }
}
