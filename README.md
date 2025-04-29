# TIN-QUIC-Marvell

This project provides two C applications to benchmark QUIC handshake.

- **server.c**: A QUIC server that can echo early-data (0-RTT) or send a fixed-size payload after handshake.
- **client.c**: A multithreaded QUIC client that measures and reports separate handshake (HS) and data-read (RD) metrics, plus throughput.

---

## Prerequisites

- **OpenSSL 3.5** (or newer) built with QUIC support
- **GCC** (or compatible C compiler) with pthreads
- POSIX-compatible OS (Linux, macOS)
- Network connectivity (for remote testing)
---

## Generating Test Certificates

Run these commands to create a self-signed server certificate for testing:

```bash
# Generate a 2048-bit RSA key and a self-signed cert valid for 1 year
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=localhost"
```

Keep `server.crt` and `server.key` in your working directory.

---

## Building

Compile both programs with OpenSSL and pthreads:

```bash
gcc -pthread server.c   -o server   -lssl -lcrypto
gcc -pthread client.c   -o client   -lssl -lcrypto
```

---

## Usage

### Server

```bash
./server <port> <server.crt> <server.key> <payload_size> [--0rtt]
```

- `<port>`: UDP port to listen on (e.g. `4433`)
- `<server.crt>` & `<server.key>`: Paths to the certificate and private key
- `<payload_size>`: Number of bytes to send post-handshake (e.g. `1024`)
- `--0rtt`: (optional) advertise and accept early-data. If omitted, server only supports 1-RTT.

**Example:**
```bash
./server 4433 server.crt server.key 1024 --0rtt
```

### Client

```bash
./client <num_threads> <mode> <duration_s> <server_ip> <server_port> <payload_size>
```

- `<num_threads>`: Number of concurrent worker threads (e.g. `4`)
- `<mode>`: `0rtt` or `1rtt`
- `<duration_s>`: Total test duration in seconds (e.g. `10`)
- `<server_ip>`: IP or hostname of the server (e.g. `127.0.0.1`)
- `<server_port>`: Port the server is listening on (e.g. `4433`)
- `<payload_size>`: Must match the server’s payload size

**Example:**
```bash
./client 4 0rtt 10 127.0.0.1 4433 1024
```

---

## Output Metrics

Every 2s the client prints:

```
[Metrics] HS-TPS: <float>, HS-Lat: <ms>  |  RD-TPS: <float>, RD-Lat: <ms>  |  Thrpt: <MiB/s>
```

- **HS-TPS**: Handshakes per second
- **HS-Lat**: Avg handshake latency (ms)
- **RD-TPS**: Data reads per second
- **RD-Lat**: Avg read latency (ms)
- **Thrpt**: Data throughput in MiB/s

At the end, a summary shows total counts and averages.

---

## Examples

#### Localhost, small payload
```bash
# Server (0-RTT enabled)
./server 4433 server.crt server.key 128 --0rtt

# Client (4 threads, 10s)
./client 4 0rtt 10 127.0.0.1 4433 128
```

#### Remote machine test
```bash
./server 4433 server.crt server.key 2048 --0rtt   # on server host
./client 8 1rtt 20 192.0.2.10 4433 2048         # on client host
```

