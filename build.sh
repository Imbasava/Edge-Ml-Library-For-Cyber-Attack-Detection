#!/bin/bash
echo "[*] Compiling C++ producer..."
# The -I flag tells the compiler where to find the nlohmann/json header
# The -lpcap flag links the libpcap library
g++ -std=c++17 -O2 producer_v2.cpp -o producer_v2 -I. -lpcap

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful. Executable 'producer_v2' created."
else
    echo "[-] Compilation failed."
fi