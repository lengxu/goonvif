# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go package for communicating with ONVIF (Open Network Video Interface) network cameras. The package provides functionality for device discovery, authentication, and control of IP cameras that support ONVIF specifications.

**🆕 Enhanced Features**: True Cross-Network Discovery with automatic device information extraction and intelligent security testing - Can discover ONVIF devices across different network segments, automatically extract detailed device information, and perform comprehensive security assessment with intelligent credential sharing between ONVIF and RTSP protocols.

## Core Architecture

The codebase is organized around several key components:

- **Device Management** (`device.go`): Core ONVIF device operations including authentication, system info, network configuration, and user management
- **Media Services** (`media.go`): Video/audio stream configuration, profiles, encoders, and snapshot functionality  
- **PTZ Control** (`ptz.go`): Pan-tilt-zoom camera movement and preset management
- **Discovery Engine** (`discovery.go`): **ENHANCED** Network discovery with cross-network capabilities, automatic device information extraction, and intelligent security testing
- **Security Testing** (`discovery.go`): Comprehensive weak credential detection with bidirectional ONVIF/RTSP credential sharing
- **SOAP Communication** (`soap.go`): Low-level SOAP/XML messaging with digest authentication support
- **Mobile Library** (`lib_onvif.go`): JSON-based API wrapper for mobile app integration
- **Data Models** (`model.go`): Core structs with extended device information and security assessment fields
- **Command Line Tool** (`cmd/onvif/main.go`): Standalone executable for device discovery and management

## Enhanced Discovery Features

### Cross-Network Discovery
- **Local Networks**: Uses WS-Discovery (UDP multicast) for fast detection
- **Cross-Network**: Uses TCP port scanning + HTTP ONVIF detection
- **Hybrid Mode**: Automatically selects optimal method based on network topology
- **Smart Detection**: Identifies local vs remote networks automatically

### Automatic Device Information Extraction
The discovery process now automatically extracts detailed device information during discovery:

- **Basic Info**: Manufacturer, Model, Hardware ID, Serial Number, Firmware Version
- **Network Info**: IP Address, Port, MAC Address, XAddr endpoints  
- **Location**: Device location information from ONVIF scopes
- **Capabilities**: Supported profiles (Media, PTZ, Events, Imaging, Recording, Analytics)
- **Services**: Available service endpoints and their URLs
- **Scopes**: Additional ONVIF scope information

### Intelligent Security Testing
Comprehensive security assessment with advanced credential testing:

- **Weak Password Detection**: Tests extensive dictionary of common weak credentials
- **Multi-Protocol Testing**: Simultaneous ONVIF and RTSP authentication testing
- **Bidirectional Credential Sharing**: If ONVIF finds credentials, automatically tests RTSP; if RTSP finds credentials, automatically tests ONVIF
- **Authentication Status Tracking**: Detailed security status for both protocols
- **Stream Discovery**: Automatic discovery of accessible RTSP streams with working credentials
- **Performance Optimized**: Rate-limited testing with delays to avoid overwhelming devices

### Discovery Input Formats
- `"auto"` or `"all"` - Auto-discover on all common private networks
- `"192.168.1.0/24"` - Single network segment (smart method selection)
- `"192.168.1.0/24,10.0.0.0/16"` - Multiple network segments (comma-separated)
- `"192.168.1.100"` - Single IP address (hybrid detection)

## Development Commands

### Build Commands
```bash
# Build cross-platform binaries with enhanced discovery (Windows x86/x64, RK3588 ARM64)
./build.sh

# Build for current platform only
go build ./cmd/onvif

# Build main library package (for development/testing)
go build

# Clean build artifacts
rm -rf build/ dist/

# Mobile builds (Android/iOS - requires gomobile)
make build      # Android AAR
make build_ios  # iOS framework
make clean      # Clean mobile build artifacts
```

### Testing Commands
```bash
# Run all tests (requires live ONVIF devices - update test files to match your network)
go test -v

# Run specific test
go test -v -run TestGetCapabilities

# List all available tests
go test -list .

# Run tests with timeout (recommended for network tests)
go test -v -timeout 30s
```

### Module Management
```bash
# Download dependencies
go mod download

# Update dependencies
go mod tidy
```

### Command Line Tool Usage
```bash
# Auto discover devices on all networks
./onvif -cmd discover -ip "auto" -timeout 10000

# Discover on specific network
./onvif -cmd discover -ip "192.168.1.0/24" -timeout 5000

# Get device information (requires authentication)
./onvif -cmd info -host http://192.168.1.100/onvif/device_service -user admin -pass 123456

# Get media capabilities
./onvif -cmd media -host http://192.168.1.100/onvif/device_service -user admin -pass 123456

# Get PTZ capabilities  
./onvif -cmd ptz -host http://192.168.1.100/onvif/device_service -user admin -pass 123456

# Security-enhanced discovery with automatic weak credential testing
./onvif -cmd discover -ip "10.1.60.0/24" -timeout 10000
# This will automatically:
# - Test weak credentials on ONVIF endpoints
# - Test RTSP authentication on discovered devices  
# - Share credentials between protocols
# - Extract detailed device information using found credentials
```

## Key Design Patterns

- **Service-oriented architecture**: Separate modules for Device, Media, PTZ, Events, and Recording services
- **SOAP client pattern**: All ONVIF communication uses SOAP requests with XML namespace handling via `soap.go`
- **Digest authentication**: Built-in support for HTTP digest auth required by ONVIF spec
- **Mobile bindings**: `lib_onvif.go` provides gomobile-compatible JSON API wrapper for cross-platform mobile apps
- **Hybrid discovery protocol**: Combines WS-Discovery + TCP scanning for maximum coverage
- **Smart network detection**: Automatically chooses optimal discovery method based on network topology
- **Intelligent security testing**: Bidirectional credential sharing between ONVIF and RTSP protocols
- **Enhanced data extraction**: Authenticated SOAP requests for comprehensive device information
- **Error handling**: Consistent error propagation through `Device.ErrorMsg` field and Go error returns

## Code Organization Patterns

- **Struct-based API**: Core operations via `Device` struct with methods like `GetCapabilities()`, `GetStreamURI()`
- **Interface compatibility**: `DeviceCapabilities` is a struct, not interface - avoid nil comparisons
- **Parameter consistency**: Methods like `GetStreamURI()` require both `profileToken` and `protocol` parameters
- **JSON marshaling**: All public API functions return JSON strings via `OnvifData` wrapper
- **Global state management**: Uses package-level maps for caching XAddr endpoints (`mapProfile`, `mapPtzXAddr`, `mapMediaXAddr`)

## Technical Implementation

### Discovery Methods
1. **WS-Discovery (Traditional)**: UDP multicast to 239.255.255.250:3702
   - Works within local broadcast domain
   - Fast and efficient for same-network devices
   - Limited by router multicast forwarding

2. **TCP Scanning (Cross-Network)**: Direct TCP connections
   - Scans common ONVIF ports: 80, 8080, 8000, 554, 8554, 5000, 10000
   - Sends HTTP SOAP requests to identify ONVIF devices
   - Works across network segments and routers

3. **Hybrid Approach**: Intelligent combination
   - Detects if target network is local or remote
   - Uses appropriate method automatically
   - Combines results and removes duplicates

### Enhanced Information Extraction
- **GetCapabilities**: Device capabilities and service endpoints
- **GetDeviceInformation**: **AUTOMATICALLY CALLED** - Manufacturer, model, serial number, hardware ID, firmware version
- **GetSystemDateAndTime**: System information and timezone
- **GetScopes**: Raw ONVIF scope information
- **GetNetworkInterfaces**: MAC address extraction
- **GetHostname**: Device hostname information
- **Scope Parsing**: ONVIF scope strings from WS-Discovery responses

### Security Testing Process
1. **Weak Credential Testing**: Tests comprehensive dictionary against ONVIF endpoints
2. **RTSP Service Discovery**: Scans common RTSP ports (554, 8554, 1935, 8935)
3. **RTSP Stream Testing**: Tests multiple stream paths with discovered credentials
4. **Bidirectional Credential Sharing**: 
   - If ONVIF finds working credentials → Test RTSP with same credentials
   - If RTSP finds working credentials → Test ONVIF with same credentials
5. **Enhanced Information Retrieval**: Use authenticated access to get detailed device info

### Device Information Enhancement Process
1. Initial discovery via WS-Discovery or TCP scanning
2. Automatic call to `enhanceDeviceInfo()` function
3. Security testing with weak credential detection
4. Multiple SOAP requests sent to extract detailed information:
   - `tryGetDeviceInformationDetails()` - Core device info (with auth if available)
   - `tryGetRawScopes()` - Scope information
   - `tryGetMACAddress()` - Network details
   - `tryGetHostname()` - Host identification
5. Cross-protocol credential sharing and validation
6. Information merged and returned in enhanced Device struct

## Dependencies

- `github.com/clbanning/mxj`: XML/JSON conversion for SOAP responses
- `github.com/golang/glog`: Structured logging with verbose output support
- `github.com/google/uuid`: UUID generation for SOAP messages

## Testing Setup

Tests require live ONVIF cameras for integration testing. Test files include:
- `device_test.go`: Device management functions (GetInformation, GetCapabilities, etc.)
- `media_test.go`: Media profile and stream operations (GetProfiles, GetStreamURI, etc.)
- `ptz_test.go`: Camera movement and positioning (ContinuousMove, AbsoluteMove, etc.)
- `get_stream_url_test.go`: Stream URL generation

**Test Configuration**: Tests expect ONVIF devices on network `192.168.0.11:80`. Update test files to match your network setup.

**Common Test Patterns**:
- Most tests follow pattern: device setup → SOAP call → response validation
- Integration tests require actual ONVIF devices (will timeout without them)
- Tests use default credentials and endpoints - modify for your devices

## Performance Considerations

- **Concurrent Scanning**: Uses controlled goroutines with semaphores (max 20 for cross-network, 50 for RTSP, 30 for HTTP)
- **Timeout Management**: Configurable timeouts (10s for ONVIF auth, 5s for general SOAP, 3s for RTSP)
- **Network Detection**: Fast local/remote network identification
- **Rate Limiting**: 200ms delays between credential attempts to prevent device overload
- **Information Caching**: Device information extracted once during discovery
- **Intelligent Credential Sharing**: Avoids redundant testing by sharing credentials between protocols

## Troubleshooting Device Information Extraction

If devices are discovered but detailed information (manufacturer, model, etc.) is missing:

1. **Authentication Required**: Some devices require credentials for `GetDeviceInformation`
   - The system automatically tests weak credentials and uses found credentials for enhanced info retrieval
2. **Network Access**: Ensure TCP access to ONVIF ports (80, 8080, etc.)
3. **SOAP Endpoint Availability**: Verify `/onvif/device_service` endpoint is accessible
4. **Enable Verbose Logging**: Use `glog.V(2)` for detailed SOAP request/response logs
5. **Check Device Compatibility**: Some devices may not support all ONVIF operations

## Security Testing Troubleshooting

If security testing is not working as expected:

1. **Timeout Issues**: Increase timeout values if devices are slow to respond
2. **Rate Limiting**: Some devices may block rapid authentication attempts - the 200ms delay helps prevent this
3. **Credential Format**: Ensure custom credentials follow "username:password" format
4. **RTSP Port Access**: Verify RTSP ports (554, 8554, etc.) are accessible
5. **Digest Authentication**: Ensure devices support HTTP Digest authentication (most ONVIF devices do)

The enhanced discovery automatically tries multiple approaches, SOAP endpoints, and intelligent credential sharing to maximize information extraction and security assessment success rate.

## Enhanced Device Information Format

The discovery process returns comprehensive device information in JSON format including security assessment results:

```json
{
  "id": "0e823c87-0f10-11b3-8133-c056e372d45f",
  "name": "HIKVISION DS-2CD2A20F-I", 
  "ip": "10.1.60.65",
  "port": 80,
  "xAddr": "http://10.1.60.65/onvif/device_service",
  "manufacturer": "HIKVISION",
  "model": "DS-2CD2A20F-I",
  "serial_number": "DS-IPC-B12H-I20191213AACHE00138503",
  "hardware_id": "DS-2CD2A20F-I",
  "firmware_version": "V5.5.84 build 191010",
  "mac_address": "c0:56:e3:72:d4:5f",
  "auth_status": "weak_auth",
  "weak_password": true,
  "user": "admin",
  "password": "12345",
  "working_creds": "admin:12345",
  "rtsp_auth_status": "weak_auth",
  "rtsp_weak_password": true,
  "rtsp_working_creds": "admin:12345",
  "rtsp_streams": [
    "rtsp://10.1.60.65:554/",
    "rtsp://10.1.60.65:554/live",
    "rtsp://10.1.60.65:554/Streaming/Channels/101"
  ],
  "capabilities": {
    "ONVIF": true,
    "RTSP": true,
    "Media": true,
    "PTZ": true
  },
  "services": {
    "Device": "http://10.1.60.65/onvif/device_service",
    "Media": "http://10.1.60.65/onvif/media_service", 
    "PTZ": "http://10.1.60.65/onvif/ptz_service",
    "RTSP": "rtsp://10.1.60.65:554"
  }
}
```

### Security Assessment Fields

- **auth_status**: ONVIF authentication status (`no_auth`, `weak_auth`, `auth_required`, `auth_failed`)
- **weak_password**: Boolean indicating if ONVIF credentials are considered weak
- **working_creds**: Discovered working ONVIF credentials in "user:pass" format
- **rtsp_auth_status**: RTSP authentication status (same values as ONVIF)
- **rtsp_weak_password**: Boolean indicating if RTSP credentials are considered weak  
- **rtsp_working_creds**: Discovered working RTSP credentials
- **rtsp_streams**: List of accessible RTSP stream URLs