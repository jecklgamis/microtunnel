# Verifying the Tunnel

Once relay and peers are running, verify connectivity using overlay IPs:

```bash
# From peer-1, ping the relay and peer-2
ping 10.9.0.1
ping 10.9.0.3

# From the relay, ping both peers
ping 10.9.0.2
ping 10.9.0.3
```
