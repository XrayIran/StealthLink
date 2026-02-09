#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacketHeader {
    pub version: u8,
    pub flags: u8,
    pub flow_id: u32,
    pub seq: u32,
    pub payload_len: u16,
}

pub const HEADER_LEN: usize = 12;

pub fn build_packet(header: &RawPacketHeader, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err("payload too large".to_string());
    }
    let mut out = vec![0u8; HEADER_LEN + payload.len()];
    out[0] = header.version;
    out[1] = header.flags;
    out[2..6].copy_from_slice(&header.flow_id.to_be_bytes());
    out[6..10].copy_from_slice(&header.seq.to_be_bytes());
    out[10..12].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[HEADER_LEN..].copy_from_slice(payload);
    Ok(out)
}

pub fn parse_packet(data: &[u8]) -> Result<(RawPacketHeader, Vec<u8>), String> {
    if data.len() < HEADER_LEN {
        return Err("packet too short".to_string());
    }
    let payload_len = u16::from_be_bytes([data[10], data[11]]) as usize;
    if data.len() < HEADER_LEN + payload_len {
        return Err("incomplete packet payload".to_string());
    }

    let header = RawPacketHeader {
        version: data[0],
        flags: data[1],
        flow_id: u32::from_be_bytes([data[2], data[3], data[4], data[5]]),
        seq: u32::from_be_bytes([data[6], data[7], data[8], data[9]]),
        payload_len: payload_len as u16,
    };
    let payload = data[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::{build_packet, parse_packet, RawPacketHeader};

    #[test]
    fn packet_round_trip() {
        let header = RawPacketHeader {
            version: 1,
            flags: 0b0101_0011,
            flow_id: 42,
            seq: 99,
            payload_len: 0,
        };
        let payload = b"hello-packet";

        let pkt = build_packet(&header, payload).expect("build");
        let (decoded, body) = parse_packet(&pkt).expect("parse");

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.flags, header.flags);
        assert_eq!(decoded.flow_id, header.flow_id);
        assert_eq!(decoded.seq, header.seq);
        assert_eq!(body, payload);
    }

    #[test]
    fn rejects_short_packets() {
        let err = parse_packet(&[1, 2, 3]).expect_err("short packet");
        assert!(err.contains("too short"));
    }
}
