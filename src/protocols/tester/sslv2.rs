use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::timeout;

pub(super) const MAX_RECORD_WITH_HEADER: usize = 32767 + 2;

pub(super) fn record_shape(data: &[u8]) -> Option<(usize, usize, usize)> {
    let first = *data.first()?;
    let second = *data.get(1)?;
    if matches!(first, 0x14..=0x18) && second == 0x03 {
        return None;
    }
    if (first & 0x80) != 0 {
        let record_len = ((first & 0x7f) as usize) << 8 | second as usize;
        Some((2, record_len, 2 + record_len))
    } else {
        let record_len = ((first & 0x3f) as usize) << 8 | second as usize;
        Some((3, record_len, 3 + record_len))
    }
}

pub(in crate::protocols::tester) fn build_client_hello() -> crate::Result<Vec<u8>> {
    let mut body = vec![0x01, 0x00, 0x02];
    body.push(0x00);
    body.push(0x09); // cipher_spec_length: 9 bytes (3 ciphers x 3 bytes each)
    body.push(0x00);
    body.push(0x00);
    body.push(0x00);
    body.push(0x10);
    body.extend_from_slice(&[0x01, 0x00, 0x80]);
    body.extend_from_slice(&[0x02, 0x00, 0x80]);
    body.extend_from_slice(&[0x03, 0x00, 0x80]);
    body.extend_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]);
    encode_client_hello_body(body)
}

fn encode_client_hello_body(body: Vec<u8>) -> crate::Result<Vec<u8>> {
    let len = body.len();
    let len = u8::try_from(len)
        .map_err(|_| crate::TlsError::Other("SSLv2 ClientHello too long".to_string()))?;
    let mut hello = vec![0x80, len];
    hello.extend_from_slice(&body);
    Ok(hello)
}

pub(super) async fn read_complete_record(
    stream: &mut tokio::net::TcpStream,
    max_len: usize,
    read_timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut response = vec![0u8; max_len];
    let mut total = 0usize;

    loop {
        if total >= response.len() {
            break;
        }
        let Some(read_buf) = response.get_mut(total..) else {
            break;
        };
        let n = match timeout(read_timeout, stream.read(read_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        total += n;
        if total >= 2 {
            let Some((header_len, _record_len, record_total)) =
                record_shape(response.get(..total).unwrap_or(&[]))
            else {
                continue;
            };
            if total < header_len {
                continue;
            }
            if record_total > response.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SSLv2 probe response length exceeds buffer",
                ));
            }
            if total >= record_total {
                break;
            }
        }
    }

    response.truncate(total);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn read_from_local_peer(response: &'static [u8], max_len: usize) -> io::Result<Vec<u8>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept local probe");
            stream
                .write_all(response)
                .await
                .expect("write local probe response");
        });
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        let result = read_complete_record(&mut stream, max_len, Duration::from_secs(1)).await;
        server.await.expect("local probe task should finish");
        result
    }

    #[test]
    fn record_shape_accepts_short_and_long_ssl_v2_headers() {
        assert_eq!(record_shape(&[]), None);
        assert_eq!(record_shape(&[0x80]), None);
        assert_eq!(record_shape(&[0x16, 0x03, 0x03]), None);
        assert_eq!(record_shape(&[0x80, 0x03]), Some((2, 3, 5)));
        assert_eq!(record_shape(&[0x01, 0x02]), Some((3, 258, 261)));
    }

    #[test]
    fn client_hello_encodes_the_body_length_and_rejects_oversized_bodies() {
        let hello = build_client_hello().expect("fixed ClientHello should build");
        assert_eq!(hello[0], 0x80);
        assert_eq!(usize::from(hello[1]) + 2, hello.len());

        let error = encode_client_hello_body(vec![0; usize::from(u8::MAX) + 1])
            .expect_err("body length does not fit the SSLv2 header");
        assert!(error.to_string().contains("SSLv2 ClientHello too long"));
    }

    #[tokio::test]
    async fn complete_record_reader_handles_empty_partial_tls_and_complete_responses() {
        for response in [
            &[][..],
            &[0x80][..],
            &[0x16, 0x03, 0x01][..],
            &[0x80, 0x01, 0x04][..],
        ] {
            assert_eq!(
                read_from_local_peer(response, 8).await.unwrap(),
                response,
                "response {response:02x?}"
            );
        }

        assert_eq!(
            read_from_local_peer(&[], 0).await.unwrap(),
            Vec::<u8>::new()
        );
    }

    #[tokio::test]
    async fn complete_record_reader_rejects_records_larger_than_its_buffer() {
        let error = read_from_local_peer(&[0x80, 0x03], 3)
            .await
            .expect_err("declared record cannot exceed the output buffer");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
