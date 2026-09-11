//! DNS over a TUN TCP stream, using the same resolver as UDP dns-hijack.
//!
//! DNS messages use a two-byte network-order length prefix (RFC 7766).
//! Keep the connection open for subsequent queries, including pipelined
//! messages, and bound every read/query/write so idle clients release slots.

use std::io;
use std::time::Duration;

use meow_dns::{DnsServer, Resolver};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const DNS_TCP_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn serve<S>(stream: &mut S, resolver: &Resolver) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve_with_timeout(stream, resolver, DNS_TCP_TIMEOUT).await
}

async fn serve_with_timeout<S>(
    stream: &mut S,
    resolver: &Resolver,
    wait: Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let exchange = async {
            // EOF between messages is a normal close. EOF partway through
            // the length or payload is a truncated DNS message.
            let mut size = [0u8; 2];
            if stream.read(&mut size[..1]).await? == 0 {
                return Ok(false);
            }
            stream.read_exact(&mut size[1..]).await?;
            let size = u16::from_be_bytes(size) as usize;
            if size < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TCP DNS message is shorter than its header",
                ));
            }
            let mut query = vec![0; size];
            stream.read_exact(&mut query).await?;
            let response = DnsServer::handle_query(&query, resolver)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let size = u16::try_from(response.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TCP DNS response exceeds 65535 bytes",
                )
            })?;
            stream.write_all(&size.to_be_bytes()).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
            Ok(true)
        };
        if !timeout(wait, exchange)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP DNS exchange timed out"))??
        {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::DnsMode;
    use meow_dns::HostEntry;
    use meow_trie::DomainTrie;

    fn resolver() -> Resolver {
        let mut hosts = DomainTrie::new();
        assert!(hosts.insert(
            "vpn.test",
            HostEntry::Addresses(vec!["198.18.0.42".parse().unwrap()]),
        ));
        Resolver::new(Vec::new(), Vec::new(), DnsMode::Normal, hosts, true)
    }

    fn query(id: u16) -> Vec<u8> {
        let mut query = vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        query[..2].copy_from_slice(&id.to_be_bytes());
        query.extend_from_slice(b"\x03vpn\x04test\x00\x00\x01\x00\x01");
        query
    }

    #[tokio::test]
    async fn fragmented_and_pipelined_queries_use_the_udp_resolver_pipeline() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move { serve(&mut server, &resolver()).await });
        let queries = [query(0x1234), query(0x5678)];
        // Split the first length prefix and query, then pipeline the second.
        client.write_all(&[0]).await.unwrap();
        tokio::task::yield_now().await;
        client.write_all(&[queries[0].len() as u8]).await.unwrap();
        client.write_all(&queries[0][..9]).await.unwrap();
        tokio::task::yield_now().await;
        client.write_all(&queries[0][9..]).await.unwrap();
        client
            .write_all(&(queries[1].len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&queries[1]).await.unwrap();
        for query in queries {
            let size = client.read_u16().await.unwrap();
            let mut response = vec![0; size as usize];
            client.read_exact(&mut response).await.unwrap();
            let expected = DnsServer::handle_query(&query, &resolver()).await.unwrap();
            assert_eq!(response, expected);
            assert_eq!(
                &response[6..8],
                &[0, 1],
                "local answer returned without upstream DNS"
            );
        }
        client.shutdown().await.unwrap();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_or_truncated_frames_close_the_connection() {
        for bytes in [&[0][..], &[0, 11], &[0, 30, 0, 1]] {
            let (mut client, mut server) = tokio::io::duplex(64);
            client.write_all(bytes).await.unwrap();
            client.shutdown().await.unwrap();
            let error = serve(&mut server, &resolver()).await.unwrap_err();
            assert!(matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ));
            let mut response = Vec::new();
            drop(server);
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_or_incomplete_clients_do_not_keep_dns_slots_forever() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[0]).await.unwrap();
        let error = serve_with_timeout(&mut server, &resolver(), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
