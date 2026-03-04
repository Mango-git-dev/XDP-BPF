#!/bin/bash

# Anti-DDoS Build Script
# Owner: t.me/deew1771

echo "--- Bắt đầu biên dịch Anti-DDoS Layer 4 ---"

# 1. Biên dịch C (eBPF)
echo "[1/2] Biên dịch eBPF Core..."
clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/core.c -o bpf/core.o

if [ $? -eq 0 ]; then
    echo ">> Biên dịch BPF thành công: bpf/core.o"
else
    echo ">> LỖI biên dịch BPF!"
    exit 1
fi

# 2. Biên dịch Go
echo "[2/2] Biên dịch Go (Dashboard & Ctrl)..."
mkdir -p bin
go mod tidy
go build -o bin/dashboard cmd/dashboard/main.go
go build -o bin/ctrl cmd/ctrl/main.go

if [ $? -eq 0 ]; then
    echo ">> Biên dịch Go thành công: bin/dashboard & bin/ctrl"
else
    echo ">> LỖI biên dịch Go!"
    exit 1
fi

echo "--- Hoàn thành! Sử dụng 'sudo ./bin/dashboard' để bắt đầu ---"
