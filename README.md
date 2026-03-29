# wgsocks

A SOCKS5 proxy that routes traffic through WireGuard VPN tunnels. Uses [wireguard-go](https://github.com/WireGuard/wireguard-go) with gVisor netstack for pure userspace tunnels — no kernel modules, no root required.

Manages a pool of tunnels with LRU eviction and round-robin load balancing with automatic failover.

## Install

```bash
go install github.com/meanie-py/wgsocks/cmd/wgsocks@latest
```

Or build from source:

```bash
go build -o wgsocks ./cmd/wgsocks
```

## Usage

```bash
wgsocks ./vpn-configs/*.conf
```

```bash
wgsocks /etc/wireguard/us.conf /etc/wireguard/de.conf
```

Then use it:

```bash
curl -x socks5h://localhost:1080 https://ipinfo.io
```

From Python:

```python
# pip install httpx[socks]
import httpx

client = httpx.Client(proxy="socks5://localhost:1080")
r = client.get("https://ipinfo.io")
print(r.json())
```

## Configuration

Operational tunables via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:1080` | SOCKS5 listen address |
| `MAX_TUNNELS` | `5` | Max concurrent WireGuard tunnels |
| `MAX_FAILOVER` | `3` | Failover attempts per connection |

## How it works

- Parses WireGuard `.conf` files passed as arguments
- Incoming SOCKS5 connections are round-robined across configs
- Tunnels are created on demand and cached in an LRU pool
- When the pool is full, the least recently used tunnel is evicted
- On connection failure, the next config in rotation is tried (up to `MAX_FAILOVER` times)

## License

[CC0 1.0](LICENSE) — public domain
