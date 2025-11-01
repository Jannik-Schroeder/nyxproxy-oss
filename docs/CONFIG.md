# Configuration Reference

This document provides detailed information about all configuration options available in NyxProxy-OSS.

## Configuration File

NyxProxy-OSS uses YAML for configuration. The default configuration file is `config.yaml` in the same directory as the binary.

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
- **Default**: `socks5`

The type of proxy server to run.

**Example**:
```yaml
proxy:
  type: socks5
```

### `proxy.listen_address`

- **Type**: `string`
- **Required**: Yes
- **Default**: `0.0.0.0`

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
- **Default**: `1080` (SOCKS5) or `8080` (HTTPS)

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
- **Default**: `true`

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

## Monitoring Settings

### `monitoring.enabled`

- **Type**: `boolean`
- **Required**: No
- **Default**: `true`

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
- **Default**: `9090`

The port for the monitoring HTTP server.

**Example**:
```yaml
monitoring:
  port: 9090
```

### `monitoring.allow_remote`

- **Type**: `boolean`
- **Required**: No
- **Default**: `false`

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
- **Default**: `1`

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

You can also specify a custom location:

```bash
# Not yet implemented, but planned for future releases
./nyxproxy --config /path/to/config.yaml
```

## Security Best Practices

1. **File Permissions**: Set restrictive permissions on your config file:
   ```bash
   chmod 600 config.yaml
   ```

2. **Strong Passwords**: Use strong, unique passwords for authentication

3. **Monitoring Access**: Keep `monitoring.allow_remote` disabled unless absolutely necessary

4. **Interface Binding**: Bind to specific interfaces instead of `0.0.0.0` when possible

5. **Firewall**: Use a firewall to restrict access to the proxy port
