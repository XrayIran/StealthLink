pub fn salamander_xor(input: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err("key must not be empty".to_string());
    }
    let mut out = Vec::with_capacity(input.len());
    for (i, b) in input.iter().enumerate() {
        let k = key[(i + (nonce as usize % key.len())) % key.len()];
        let salt = ((nonce >> ((i % 8) * 8)) & 0xff) as u8;
        out.push(*b ^ k ^ salt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::salamander_xor;

    #[test]
    fn xor_is_reversible() {
        let input = b"udp-obfuscation";
        let key = b"secret-key";
        let nonce = 12345;

        let obfs = salamander_xor(input, key, nonce).expect("obfuscate");
        assert_ne!(obfs, input);

        let plain = salamander_xor(&obfs, key, nonce).expect("deobfuscate");
        assert_eq!(plain, input);
    }

    #[test]
    fn empty_key_is_rejected() {
        let err = salamander_xor(b"data", b"", 1).expect_err("empty key");
        assert!(err.contains("must not be empty"));
    }
}
