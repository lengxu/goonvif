#!/bin/bash

# Build script for ONVIF tool
# Supports Windows x86 and RK3588 ARM64 platforms

set -e

PROJECT_NAME="onvif"
VERSION=$(date +%Y%m%d_%H%M%S)
BUILD_DIR="build"
DIST_DIR="dist"

echo "Building ONVIF tool..."
echo "Project: $PROJECT_NAME"
echo "Version: $VERSION"
echo ""

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf $BUILD_DIR
rm -rf $DIST_DIR
mkdir -p $BUILD_DIR
mkdir -p $DIST_DIR

# Get dependencies
echo "Downloading dependencies..."
go mod download
go mod tidy

# Build for Windows x86 (32-bit)
echo "Building for Windows x86..."
export GOOS=windows
export GOARCH=386
export CGO_ENABLED=0
go build -ldflags "-s -w -X main.version=$VERSION" -o $BUILD_DIR/${PROJECT_NAME}_windows_x86.exe ./cmd/onvif/main.go
echo "✓ Windows x86 binary created: $BUILD_DIR/${PROJECT_NAME}_windows_x86.exe"

# Build for Windows x64 (64-bit) - in case needed
echo "Building for Windows x64..."
export GOOS=windows
export GOARCH=amd64
export CGO_ENABLED=0
go build -ldflags "-s -w -X main.version=$VERSION" -o $BUILD_DIR/${PROJECT_NAME}_windows_x64.exe ./cmd/onvif/main.go
echo "✓ Windows x64 binary created: $BUILD_DIR/${PROJECT_NAME}_windows_x64.exe"

# Build for RK3588 ARM64 (Linux)
echo "Building for RK3588 ARM64..."
export GOOS=linux
export GOARCH=arm64
export CGO_ENABLED=0
go build -ldflags "-s -w -X main.version=$VERSION" -o $BUILD_DIR/${PROJECT_NAME}_rk3588_arm64 ./cmd/onvif/main.go
echo "✓ RK3588 ARM64 binary created: $BUILD_DIR/${PROJECT_NAME}_rk3588_arm64"

# Build for current platform (for testing)
echo "Building for current platform..."
unset GOOS
unset GOARCH
export CGO_ENABLED=0
go build -ldflags "-s -w -X main.version=$VERSION" -o $BUILD_DIR/${PROJECT_NAME}_local ./cmd/onvif/main.go
echo "✓ Local binary created: $BUILD_DIR/${PROJECT_NAME}_local"

# Create distribution packages
echo ""
echo "Creating distribution packages..."

# Copy binaries to dist directory with version names
cp $BUILD_DIR/${PROJECT_NAME}_windows_x86.exe $DIST_DIR/${PROJECT_NAME}_windows_x86_$VERSION.exe
echo "✓ Windows x86 package: $DIST_DIR/${PROJECT_NAME}_windows_x86_$VERSION.exe"

cp $BUILD_DIR/${PROJECT_NAME}_windows_x64.exe $DIST_DIR/${PROJECT_NAME}_windows_x64_$VERSION.exe
echo "✓ Windows x64 package: $DIST_DIR/${PROJECT_NAME}_windows_x64_$VERSION.exe"

cp $BUILD_DIR/${PROJECT_NAME}_rk3588_arm64 $DIST_DIR/${PROJECT_NAME}_rk3588_arm64_$VERSION
echo "✓ RK3588 ARM64 package: $DIST_DIR/${PROJECT_NAME}_rk3588_arm64_$VERSION"

# Try to create archives if tools are available
if command -v zip >/dev/null 2>&1; then
    cd $BUILD_DIR
    zip ../$DIST_DIR/${PROJECT_NAME}_windows_x86_$VERSION.zip ${PROJECT_NAME}_windows_x86.exe
    zip ../$DIST_DIR/${PROJECT_NAME}_windows_x64_$VERSION.zip ${PROJECT_NAME}_windows_x64.exe
    cd ..
    echo "✓ ZIP archives created"
fi

if command -v tar >/dev/null 2>&1; then
    tar -czf $DIST_DIR/${PROJECT_NAME}_rk3588_arm64_$VERSION.tar.gz -C $BUILD_DIR ${PROJECT_NAME}_rk3588_arm64
    echo "✓ TAR archive created"
fi

# Display file sizes
echo ""
echo "Build completed! File sizes:"
ls -lh $BUILD_DIR/
echo ""
echo "Distribution packages:"
ls -lh $DIST_DIR/

# Create usage instructions
cat > $DIST_DIR/README.txt << EOF
ONVIF Device Management Tool - Cross-Network Discovery Edition
============================================================

Build Date: $(date)
Version: $VERSION

New Features in This Version:
----------------------------
✓ TRUE Cross-Network Discovery - Works across different network segments
✓ Hybrid Discovery Strategy - Combines WS-Discovery and TCP scanning
✓ Smart Network Detection - Automatically chooses optimal discovery method
✓ Enhanced Device Detection - HTTP-based ONVIF device identification

Files:
------
- ${PROJECT_NAME}_windows_x86.exe    - Windows 32-bit executable
- ${PROJECT_NAME}_windows_x64.exe    - Windows 64-bit executable  
- ${PROJECT_NAME}_rk3588_arm64       - RK3588 ARM64 Linux executable

Discovery Methods:
-----------------
Local Networks: Uses WS-Discovery (UDP multicast) for fast detection
Cross-Network:  Uses TCP port scanning + HTTP ONVIF detection
Hybrid Mode:    Combines both methods for maximum device discovery

Usage Examples:
--------------
# Auto discover devices on all common networks (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
./${PROJECT_NAME} -cmd discover -ip "auto" -timeout 10000

# Discover devices on specific network segment (works cross-network!)
./${PROJECT_NAME} -cmd discover -ip "192.168.1.0/24" -timeout 5000

# Discover devices on multiple network segments
./${PROJECT_NAME} -cmd discover -ip "192.168.1.0/24,10.0.0.0/24,172.16.0.0/24" -timeout 8000

# Discover devices on single IP (hybrid detection)
./${PROJECT_NAME} -cmd discover -ip "192.168.1.100" -timeout 3000

# Get device information
./${PROJECT_NAME} -cmd info -host http://192.168.1.100/onvif/device_service -user admin -pass 123456

# Get media capabilities
./${PROJECT_NAME} -cmd media -host http://192.168.1.100/onvif/device_service -user admin -pass 123456

# Get PTZ capabilities
./${PROJECT_NAME} -cmd ptz -host http://192.168.1.100/onvif/device_service -user admin -pass 123456

# Show help
./${PROJECT_NAME} -help

Discovery Input Formats:
-----------------------
- "auto" or "all"              → Auto-discover on all common private networks
- "192.168.1.0/24"            → Single network segment (smart method selection)
- "192.168.1.0/24,10.0.0.0/8" → Multiple network segments (comma-separated)
- "192.168.1.100"             → Single IP address (hybrid detection)

Technical Details:
-----------------
• WS-Discovery: Uses UDP multicast (239.255.255.250:3702) for local network discovery
• TCP Scanning: Scans ports 80, 8080, 8000, 554, 8554, 5000, 10000 for cross-network discovery
• HTTP Detection: Sends GetCapabilities SOAP requests to identify ONVIF devices
• Smart Routing: Automatically detects if target network is local or remote
• Concurrent Processing: High-performance parallel scanning with rate limiting

For RK3588 deployment:
---------------------
1. Copy ${PROJECT_NAME}_rk3588_arm64 to your RK3588 device
2. Make it executable: chmod +x ${PROJECT_NAME}_rk3588_arm64
3. Run cross-network discovery: ./${PROJECT_NAME}_rk3588_arm64 -cmd discover -ip "auto" -timeout 10000

For Windows deployment:
----------------------
1. Copy ${PROJECT_NAME}_windows_x86.exe or ${PROJECT_NAME}_windows_x64.exe to your Windows PC
2. Open Command Prompt or PowerShell
3. Run cross-network discovery: ${PROJECT_NAME}_windows_x86.exe -cmd discover -ip "auto" -timeout 10000

Performance Tips:
----------------
• Use "auto" for comprehensive discovery across all networks
• Increase timeout for large network segments (recommended: 5-10 seconds)
• Use specific CIDR ranges for faster targeted discovery
• For cross-network discovery, ensure target networks are accessible via TCP

This version can discover ONVIF cameras across ANY network segment that is reachable via TCP,
not limited to the local broadcast domain like traditional WS-Discovery implementations.
EOF

echo ""
echo "Usage instructions created: $DIST_DIR/README.txt"
echo ""
echo "=========================================="
echo "🎯 Cross-Network Discovery Build Complete!"
echo "=========================================="
echo ""
echo "✨ New Features:"
echo "  • TRUE cross-network discovery capability"
echo "  • Hybrid WS-Discovery + TCP scanning"
echo "  • Smart network detection"
echo "  • Enhanced ONVIF device identification"
echo ""
echo "📁 Build artifacts:"
echo "  • $BUILD_DIR/ - Raw binaries"
echo "  • $DIST_DIR/ - Distribution packages with documentation"
echo ""
echo "🚀 Ready for deployment on:"
echo "  • Windows x86/x64 systems"
echo "  • RK3588 ARM64 Linux devices"
echo ""
echo "💡 Quick test command:"
echo "  $BUILD_DIR/${PROJECT_NAME}_local -cmd discover -ip \"auto\" -timeout 10000"
echo ""
echo "This version can now discover ONVIF cameras across ANY"
echo "reachable network segment, not just the local broadcast domain!"