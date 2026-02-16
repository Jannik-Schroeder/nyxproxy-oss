# Configuration Reference

This document provides detailed information about all configuration options available in NyxProxy-OSS.

## Configuration File

NyxProxy-OSS uses YAML for configuration.

NyxProxy reads `config.yaml` from the **current working directory** (CWD). In systemd, this is the unit's `WorkingDirectory=`.

If no `config.yaml` is present, NyxProxy falls back to legacy environment variables (see below).

## Configuration Structure

```yaml
proxy:
  type: string
  listen_address: string
  listen_port: integer
  username: string
  password: string

network:
  interface_name: string
  ipv4_enabled: boolean
  ipv6_enabled: boolean
  rotate_ipv6: boolean
  ipv6_subnet: string
  ipv6_pool_size: integer
  ipv6_max_usage: integer
  ipv6_max_age: integer

monitoring:
  enabled: boolean
  port: integer
  allow_remote: boolean

logging:
  debug_level: integer
```

## Proxy Settings

### `proxy.type`

- **Type**: `string`
- **Required**: Yes
- **Values**: `socks5` or `https`
- **Default**: No implicit default when using `config.yaml` (use `config.example.yaml` as a starting point)

The type of proxy server to run.

**Example**:
```yaml
proxy:
  type: socks5
```

### `proxy.listen_address`

- **Type**: `string`
- **Required**: Yes
- **Default**: No implicit default when using `config.yaml` (use `config.example.yaml` as a starting point)

The IP address to bind the proxy server to.

- `0.0.0.0` - Listen on all interfaces (IPv4)
- `::` - Listen on all interfaces (IPv6)
- Specific IP - Listen only on that IP

**Example**:
```yaml
proxy:
  listen_address: 0.0.0.0
```

### `proxy.listen_port`

- **Type**: `integer`
- **Required**: Yes
- **Range**: 1-65535
- **Default**: No implicit default when using `config.yaml` (use `config.example.yaml` as a starting point)

The port number to listen on.

**Common ports**:
- `1080` - Standard SOCKS5 port
- `8080` - Standard HTTP proxy port
- `3128` - Alternative HTTP proxy port

**Example**:
```yaml
proxy:
  listen_port: 1080
```

### `proxy.username`

- **Type**: `string`
- **Required**: Yes

The username for proxy authentication.

**Example**:
```yaml
proxy:
  username: admin
```

### `proxy.password`

- **Type**: `string`
- **Required**: Yes

The password for proxy authentication.

**Security Note**: Ensure the `config.yaml` file has restricted permissions (600) to protect the password.

**Example**:
```yaml
proxy:
  password: very_secure_password_here
```

## Network Settings

### `network.interface_name`

- **Type**: `string`
- **Required**: No
- **Default**: `""` (auto-detect)

The name of the network interface to use for outgoing connections.

- Empty string (`""`) - Automatically detect the best interface
- Interface name - Use a specific interface (e.g., `eth0`, `wlan0`, `ens33`)

**Example**:
```yaml
network:
  interface_name: "eth0"
```

To list available interfaces:
```bash
ip addr show
# or
ifconfig
```

### `network.ipv4_enabled`

- **Type**: `boolean`
- **Required**: Yes
- **Default**: `true` (env fallback)

Enable IPv4 for outgoing connections.

**Example**:
```yaml
network:
  ipv4_enabled: true
```

### `network.ipv6_enabled`

- **Type**: `boolean`
- **Required**: Yes
- **Default**: `false`

Enable IPv6 for outgoing connections.

**Note**: At least one of IPv4 or IPv6 must be enabled.

**Example**:
```yaml
network:
  ipv6_enabled: false
```

### `network.rotate_ipv6`

- **Type**: `boolean`
- **Required**: No
- **Default**: `false` (env fallback)

Enable IPv6 rotation using a pre-populated pool of random IPv6 addresses from `network.ipv6_subnet`.

**Notes**:
- Linux only; requires root (or `CAP_NET_ADMIN`) because NyxProxy assigns/removes IPv6 addresses on the interface.
- NyxProxy will warn if `ndppd` is not running; for most providers you must configure `ndppd` for the routed `/64`.

### `network.ipv6_subnet`

- **Type**: `string`
- **Required**: Yes (if `network.rotate_ipv6` is `true`)

IPv6 subnet (typically a routed `/64`) used to generate random outgoing IPv6 addresses.

**Example**:
```yaml
network:
  rotate_ipv6: true
  ipv6_subnet: "2a05:f480:1800:25db::/64"
```

### `network.ipv6_pool_size`

- **Type**: `integer`
- **Required**: No
- **Default**: `200`

How many IPv6 addresses NyxProxy assigns to the interface at startup.

### `network.ipv6_max_usage`

- **Type**: `integer`
- **Required**: No
- **Default**: `100`

Rotate an IP after it has been used this many times.

### `network.ipv6_max_age`

- **Type**: `integer`
- **Required**: No
- **Default**: `30`

Rotate an IP after this many minutes.

## Monitoring Settings

### `monitoring.enabled`

- **Type**: `boolean`
- **Required**: No
- **Default**: `true` (env fallback)

Enable the monitoring HTTP server.

**Example**:
```yaml
monitoring:
  enabled: true
```

### `monitoring.port`

- **Type**: `integer`
- **Required**: No (if monitoring is enabled)
- **Range**: 1-65535
- **Default**: `9090` (env fallback)

The port for the monitoring HTTP server.

**Example**:
```yaml
monitoring:
  port: 9090
```

### `monitoring.allow_remote`

- **Type**: `boolean`
- **Required**: No
- **Default**: `false` (env fallback)

Allow remote access to the monitoring endpoints.

- `false` - Only accessible from localhost (127.0.0.1)
- `true` - Accessible from any IP address

**Security Warning**: Only set this to `true` if you understand the security implications. The monitoring endpoints do not require authentication.

**Example**:
```yaml
monitoring:
  allow_remote: false
```

## Logging Settings

### `logging.debug_level`

- **Type**: `integer`
- **Required**: No
- **Range**: 0-2
- **Default**: No implicit default when using `config.yaml` (env fallback uses `0`)

Control the verbosity of log output.

- `0` - No debug output (errors only)
- `1` - Basic logging (connection info)
- `2` - Detailed logging (full request/response details)

**Example**:
```yaml
logging:
  debug_level: 1
```

## Environment Variables (Legacy)

For backward compatibility, these environment variables are supported:

| Variable | Config Equivalent | Example |
|----------|------------------|---------|
| `PROXY_TYPE` | `proxy.type` | `socks5` |
| `PROXY_LISTEN_ADDRESS` | `proxy.listen_address` | `0.0.0.0` |
| `PROXY_LISTEN_PORT` | `proxy.listen_port` | `1080` |
| `PROXY_USERNAME` | `proxy.username` | `admin` |
| `PROXY_PASSWORD` | `proxy.password` | `password` |
| `NETWORK_INTERFACE` | `network.interface_name` | `eth0` |
| `PROXY_PROTOCOL` | IPv4/IPv6 selection | `4` or `6` |
| `MONITORING_ENABLED` | `monitoring.enabled` | `true` |
| `MONITORING_PORT` | `monitoring.port` | `9090` |
| `MONITORING_ALLOW_REMOTE` | `monitoring.allow_remote` | `false` |
| `DEBUG_LEVEL` | `logging.debug_level` | `1` |

**Note**: Configuration file settings take precedence over environment variables.

If you run without a `config.yaml`, NyxProxy uses these defaults:
- `PROXY_TYPE=https`
- `PROXY_LISTEN_ADDRESS=0.0.0.0`
- `PROXY_LISTEN_PORT=8080`
- `PROXY_PROTOCOL=4` (IPv4 outbound)
- `MONITORING_ENABLED=true`, `MONITORING_PORT=9090`, `MONITORING_ALLOW_REMOTE=false`
- `DEBUG_LEVEL=0`

**Limitations**:
- IPv6 rotation (`rotate_ipv6`, `ipv6_subnet`, pool settings) is only configurable via `config.yaml`.

## Complete Example

```yaml
proxy:
  type: socks5
  listen_address: 0.0.0.0
  listen_port: 1080
  username: admin
  password: super_secret_password

network:
  interface_name: "eth0"
  ipv4_enabled: true
  ipv6_enabled: true

  # IPv6 rotation (optional)
  rotate_ipv6: false
  ipv6_subnet: ""
  ipv6_pool_size: 200
  ipv6_max_usage: 100
  ipv6_max_age: 30

monitoring:
  enabled: true
  port: 9090
  allow_remote: false

logging:
  debug_level: 1
```

## Configuration File Location

NyxProxy-OSS looks for `config.yaml` in the following order:

1. Current working directory
2. Falls back to environment variables

Custom config file paths/flags (for example `--config`) are not implemented. To run with a different config, start the process in a different working directory (or adjust your systemd `WorkingDirectory=`).

## Security Best Practices

1. **File Permissions**: Set restrictive permissions on your config file:
   ```bash
   chmod 600 config.yaml
   ```

2. **Strong Passwords**: Use strong, unique passwords for authentication

3. **Monitoring Access**: Keep `monitoring.allow_remote` disabled unless absolutely necessary

4. **Interface Binding**: Bind to specific interfaces instead of `0.0.0.0` when possible

5. **Firewall**: Use a firewall to restrict access to the proxy port
