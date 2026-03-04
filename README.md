## 👤 Owner & Support
- **Telegram:** [t.me/deew1771](https://t.me/deew1771)

# INSTALLATION

```bash
sudo apt update && sudo apt install -y clang llvm libbpf-dev m4 make golang-go screen
make
```

# USAGE (Run in Screen Session)

```bash
screen -dmS anti sudo ./dashboard
```

# MANUAL CONTROL

```bash
# Show all commands
sudo ./ctrl help

# Update whitelist from file
sudo ./ctrl whitelist load whitelist.txt

# Lock protection stage (0-3)
sudo ./ctrl stage 0
```

# CHECK

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```



