use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_RECORD_HEADER_SIZE};
use tokio::io::AsyncReadExt;

pub(super) async fn read_tls_record(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; TLS_RECORD_HEADER_SIZE];
    if stream.read_exact(&mut header).await.is_err() {
        return Ok(None);
    }

    let Some(total_len) = total_len(&header)? else {
        return Ok(None);
    };
    let mut response = vec![0u8; total_len];
    response[..TLS_RECORD_HEADER_SIZE].copy_from_slice(&header);
    if stream
        .read_exact(&mut response[TLS_RECORD_HEADER_SIZE..])
        .await
        .is_err()
    {
        return Ok(None);
    }

    Ok(Some(response))
}

pub(super) fn total_len(header: &[u8; TLS_RECORD_HEADER_SIZE]) -> std::io::Result<Option<usize>> {
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = TLS_RECORD_HEADER_SIZE
        .checked_add(record_len)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLS record length overflow",
            )
        })?;
    if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
        return Ok(None);
    }
    Ok(Some(total_len))
}

#[cfg(test)]
mod tests {
    use super::{read_tls_record, total_len};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    async fn stream_with_response(bytes: Vec<u8>) -> (TcpStream, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let client = TcpStream::connect(address)
            .await
            .expect("client should connect to loopback");
        let (mut server, _) = listener
            .accept()
            .await
            .expect("loopback connection should be accepted");
        let writer = tokio::spawn(async move {
            server
                .write_all(&bytes)
                .await
                .expect("response bytes should be written");
        });

        (client, writer)
    }

    #[test]
    fn record_length_rejects_payloads_over_the_configured_limit() {
        let header = [0x16, 0x03, 0x03, 0xff, 0xff];
        assert_eq!(total_len(&header).unwrap(), None);
    }

    #[tokio::test]
    async fn reads_a_complete_record() {
        let response = [0x16, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let (mut client, writer) = stream_with_response(response.to_vec()).await;

        assert_eq!(
            read_tls_record(&mut client).await.unwrap(),
            Some(response.to_vec())
        );
        writer.await.expect("response writer should finish");
    }

    #[tokio::test]
    async fn incomplete_headers_and_payloads_are_reported_as_missing_records() {
        let (mut short_header, writer) = stream_with_response(vec![0x16, 0x03]).await;
        assert_eq!(read_tls_record(&mut short_header).await.unwrap(), None);
        writer.await.expect("response writer should finish");

        let (mut short_payload, writer) =
            stream_with_response(vec![0x16, 0x03, 0x03, 0x00, 0x02, 0xaa]).await;
        assert_eq!(read_tls_record(&mut short_payload).await.unwrap(), None);
        writer.await.expect("response writer should finish");
    }

    #[tokio::test]
    async fn oversized_records_are_discarded_after_the_header() {
        let response = [0x16, 0x03, 0x03, 0xff, 0xff].to_vec();
        let (mut client, writer) = stream_with_response(response).await;

        assert_eq!(read_tls_record(&mut client).await.unwrap(), None);
        writer.await.expect("response writer should finish");
    }
}
