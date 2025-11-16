#!/bin/bash
# Filename: compile_all.sh
# Purpose: Compile all feature extractors

echo "Compiling all feature extractors..."

echo "[1] Compiling C2C feature extractor..."
g++ -std=c++11 -o feature_extractor_c2c feature_extractor_c2c.cpp -lpcap -I.
if [ $? -eq 0 ]; then
    echo "✓ C2C feature extractor compiled successfully"
else
    echo "✗ Failed to compile C2C feature extractor"
    exit 1
fi

echo "[2] Compiling MITM feature extractor..."
g++ -std=c++11 -o feature_extractor_mitm feature_extractor_mitm.cpp -lpcap -I.
if [ $? -eq 0 ]; then
    echo "✓ MITM feature extractor compiled successfully"
else
    echo "✗ Failed to compile MITM feature extractor"
    exit 1
fi

echo "[3] Compiling DDoS feature extractor..."
g++ -std=c++11 -o feature_extractor_ddos feature_extractor_ddos.cpp -lpcap -I.
if [ $? -eq 0 ]; then
    echo "✓ DDoS feature extractor compiled successfully"
else
    echo "✗ Failed to compile DDoS feature extractor"
    exit 1
fi

echo ""
echo "🎉 All feature extractors compiled successfully!"
echo "Generated executables:"
echo "  - feature_extractor_c2c"
echo "  - feature_extractor_mitm" 
echo "  - feature_extractor_ddos"