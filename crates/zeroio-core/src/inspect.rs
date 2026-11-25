//! Zero-copy protocol inspection for TLS SNI (`ClientHello`) and QUIC packet headers.

/// Result of inspecting a TLS record buffer for SNI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsSniResult<'a> {
    /// Found a UTF-8 server name in the `server_name` extension.
    Found(&'a str),
    /// Need more bytes from the TCP stream before deciding.
    Incomplete,
    /// Not a valid TLS `ClientHello` or no `server_name` extension present.
    Absent,
}

/// Extract the TLS `server_name` (SNI) hostname from a TCP payload prefix
/// without allocating.
pub fn extract_tls_sni(data: &[u8]) -> TlsSniResult<'_> {
    // TLS record header: type(1)=0x16, version(2), length(2)
    if data.len() < 5 {
        return TlsSniResult::Incomplete;
    }
    if data[0] != 0x16 {
        return TlsSniResult::Absent;
    }
    let record_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
    if data.len() < 5 + record_len {
        return TlsSniResult::Incomplete;
    }
    let hs = &data[5..5 + record_len];
    // Handshake header: msg_type(1)=0x01 (ClientHello), length(3)
    if hs.len() < 4 {
        return TlsSniResult::Incomplete;
    }
    if hs[0] != 0x01 {
        return TlsSniResult::Absent;
    }
    let hs_len = (usize::from(hs[1]) << 16) | (usize::from(hs[2]) << 8) | usize::from(hs[3]);
    if hs.len() < 4 + hs_len {
        return TlsSniResult::Incomplete;
    }
    let body = &hs[4..4 + hs_len];
    // client_version(2) + random(32)
    let mut pos = 34usize;
    if body.len() <= pos {
        return TlsSniResult::Absent;
    }
    // session_id
    let sid_len = usize::from(body[pos]);
    pos += 1 + sid_len;
    if body.len() < pos + 2 {
        return TlsSniResult::Absent;
    }
    // cipher_suites
    let cs_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
    pos += 2 + cs_len;
    if body.len() <= pos {
        return TlsSniResult::Absent;
    }
    // compression_methods
    let comp_len = usize::from(body[pos]);
    pos += 1 + comp_len;
    if body.len() < pos + 2 {
        return TlsSniResult::Absent;
    }
    // extensions
    let ext_total = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
    pos += 2;
    let ext_end = pos.saturating_add(ext_total);
    if body.len() < ext_end {
        return TlsSniResult::Absent;
    }
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([body[pos + 2], body[pos + 3]]));
        pos += 4;
        if pos + ext_len > ext_end {
            return TlsSniResult::Absent;
        }
        if ext_type == 0x0000 {
            let ext = &body[pos..pos + ext_len];
            if ext.len() < 2 {
                return TlsSniResult::Absent;
            }
            let list_len = usize::from(u16::from_be_bytes([ext[0], ext[1]]));
            let mut epos = 2usize;
            let list_end = (2 + list_len).min(ext.len());
            while epos + 3 <= list_end {
                let name_type = ext[epos];
                let name_len = usize::from(u16::from_be_bytes([ext[epos + 1], ext[epos + 2]]));
                epos += 3;
                if epos + name_len > list_end {
                    return TlsSniResult::Absent;
                }
                if name_type == 0x00 {
                    return match core::str::from_utf8(&ext[epos..epos + name_len]) {
                        Ok(host) => TlsSniResult::Found(host),
                        Err(_) => TlsSniResult::Absent,
                    };
                }
                epos += name_len;
            }
            return TlsSniResult::Absent;
        }
        pos += ext_len;
    }
    TlsSniResult::Absent
}

/// Parsed QUIC header summary for stateless L4 demuxing and DCID routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicHeader<'a> {
    Long {
        version: u32,
        packet_type: u8,
        dcid: &'a [u8],
        scid: &'a [u8],
    },
    Short {
        dcid: &'a [u8],
    },
}

/// Inspect a UDP payload as a QUIC packet header.
///
/// For short-header packets, `expected_dcid_len` specifies the connection ID
/// length configured by the server endpoint (RFC 9000 §17.3).
pub fn inspect_quic_header(datagram: &[u8], expected_dcid_len: usize) -> Option<QuicHeader<'_>> {
    let first = *datagram.first()?;
    // Fixed bit (0x40) must be set on QUIC v1/v2 packets.
    if (first & 0x40) == 0 {
        return None;
    }
    let is_long = (first & 0x80) != 0;
    if !is_long {
        if expected_dcid_len > 20 || datagram.len() < 1 + expected_dcid_len {
            return None;
        }
        return Some(QuicHeader::Short {
            dcid: &datagram[1..1 + expected_dcid_len],
        });
    }
    // Long header: flags(1) + version(4) + dcid_len(1)
    if datagram.len() < 6 {
        return None;
    }
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    let dcid_len = usize::from(datagram[5]);
    if dcid_len > 20 || datagram.len() < 6 + dcid_len + 1 {
        return None;
    }
    let dcid = &datagram[6..6 + dcid_len];
    let scid_len = usize::from(datagram[6 + dcid_len]);
    if scid_len > 20 || datagram.len() < 7 + dcid_len + scid_len {
        return None;
    }
    let scid = &datagram[7 + dcid_len..7 + dcid_len + scid_len];
    let packet_type = (first & 0x30) >> 4;
    Some(QuicHeader::Long {
        version,
        packet_type,
        dcid,
        scid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni_from_client_hello() {
        let host = b"cdn.example.com";
        let mut sni_ext = Vec::new();
        let list_len = (1 + 2 + host.len()) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes()); // server_name type
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // cipher suite
        body.push(1);
        body.push(0); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        assert_eq!(extract_tls_sni(&record[..10]), TlsSniResult::Incomplete);
        assert_eq!(
            extract_tls_sni(&record),
            TlsSniResult::Found("cdn.example.com")
        );
    }

    #[test]
    fn inspects_quic_long_and_short_headers() {
        let long = [
            0xC0, // Long header + fixed bit + Initial(0)
            0x00, 0x00, 0x00, 0x01, // QUIC v1
            0x04, 0xde, 0xad, 0xbe, 0xef, // DCID len 4
            0x02, 0xca, 0xfe, // SCID len 2
        ];
        assert_eq!(
            inspect_quic_header(&long, 4),
            Some(QuicHeader::Long {
                version: 1,
                packet_type: 0,
                dcid: &[0xde, 0xad, 0xbe, 0xef],
                scid: &[0xca, 0xfe],
            })
        );

        let short = [0x40, 0x01, 0x02, 0x03, 0x04, 0x99];
        assert_eq!(
            inspect_quic_header(&short, 4),
            Some(QuicHeader::Short {
                dcid: &[0x01, 0x02, 0x03, 0x04],
            })
        );
    }
}
