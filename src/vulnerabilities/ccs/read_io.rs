use crate::Result;
use tokio::io::AsyncReadExt;

pub(super) async fn read_complete_tls_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = 5 + record_len;
    if total_len > buffer.len() {
        return Err(crate::TlsError::ParseError {
            message: "CCS TLS record length exceeds buffer".to_string(),
        });
    }

    buffer[..5].copy_from_slice(&header);
    stream.read_exact(&mut buffer[5..total_len]).await?;
    Ok(total_len)
}

#[cfg(test)]
mod tests {
    use super::read_complete_tls_record;
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

    #[tokio::test]
    async fn reads_header_and_complete_record_payload() {
        let response = [0x16, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let (mut client, writer) = stream_with_response(response.to_vec()).await;
        let mut buffer = [0; 8];

        let length = read_complete_tls_record(&mut client, &mut buffer)
            .await
            .expect("complete TLS record should be read");
        writer.await.expect("response writer should finish");

        assert_eq!(length, response.len());
        assert_eq!(buffer, response);
    }

    #[tokio::test]
    async fn rejects_record_larger_than_destination_buffer() {
        let response = [0x16, 0x03, 0x03, 0xff, 0xff];
        let (mut client, writer) = stream_with_response(response.to_vec()).await;
        let mut buffer = [0; 7];

        let error = read_complete_tls_record(&mut client, &mut buffer)
            .await
            .expect_err("record that exceeds the buffer should fail");
        writer.await.expect("response writer should finish");

        assert!(error.to_string().contains("exceeds buffer"));
    }

    #[tokio::test]
    async fn rejects_peer_closing_before_header_is_complete() {
        let (mut client, writer) = stream_with_response(vec![0x16, 0x03]).await;
        let mut buffer = [0; 16];

        assert!(
            read_complete_tls_record(&mut client, &mut buffer)
                .await
                .is_err()
        );
        writer.await.expect("response writer should finish");
    }

    #[tokio::test]
    async fn rejects_peer_closing_before_payload_is_complete() {
        let response = [0x16, 0x03, 0x03, 0x00, 0x02, 0xaa];
        let (mut client, writer) = stream_with_response(response.to_vec()).await;
        let mut buffer = [0; 16];

        assert!(
            read_complete_tls_record(&mut client, &mut buffer)
                .await
                .is_err()
        );
        writer.await.expect("response writer should finish");
    }
}
