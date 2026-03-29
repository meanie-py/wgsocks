# wgsocks

SOCKS5 proxy that routes connections through WireGuard VPN tunnels. Uses wireguard-go with gVisor netstack (pure userspace, no kernel modules). Manages a pool of tunnels with LRU eviction.

This project is fully AI-assisted ("vibecoded"). All code, tests, CI, and documentation were written with Claude.

## Structure

```
cmd/wgsocks/main.go              # Entry point, CLI arg parsing
internal/server/socks5.go        # SOCKS5 server (no auth, round-robin)
internal/wireguard/
  config.go                      # .conf file parser
  tunnel.go                      # Tunnel + TunnelPool (LRU)
vpn-configs/                     # WireGuard .conf files (gitignored)
```

## Usage

```bash
wgsocks ./vpn-configs/*.conf
```

Env vars for tunables: `LISTEN_ADDR` (`:1080`), `MAX_TUNNELS` (`5`), `MAX_FAILOVER` (`3`).
