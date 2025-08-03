package onvif

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/clbanning/mxj"
	"github.com/golang/glog"
	"github.com/google/uuid"
	onvifDigest "github.com/quocson95/go-onvif/digest"
)

var errWrongDiscoveryResponse = errors.New("Response is not related to discovery request ")

// ONVIF common ports to scan
var onvifPorts = []int{80, 8080, 8000, 554, 8554, 5000, 10000}

// RTSP ports for additional device discovery
var rtspPorts = []int{554, 8554, 1935, 8935}

// ONVIF service paths to try
var onvifPaths = []string{
	"/onvif/device_service",
	"/onvif/Device",
	"/device_service",
	"/Device",
}

// Common weak credentials for ONVIF cameras
var weakCredentials = [][]string{
	{"", ""},                   // No authentication
	{"admin", ""},              // Empty password
	{"admin", "admin"},         // Default admin
	{"admin", "123456"},        // Weak numeric password
	{"admin", "12345"},         // Short numeric
	{"admin", "password"},      // Dictionary word
	{"admin", "888888"},        // Chinese lucky number
	{"user", "user"},           // Default user
	{"root", "root"},           // Linux default
	{"guest", "guest"},         // Guest account
	{"admin", "admin123"},      // Admin with numbers
	{"admin", "111111"},        // Repeated numbers
	{"admin", "000000"},        // All zeros
	{"service", "service"},     // Service account
	{"operator", "operator"},   // Operator account
	{"admin", "abcd1234"},      // Hikvision default
	{"dahua", "dahua"},         // Dahua default
	{"uniview", "uniview"},     // Uniview default
	{"admin", "9999"},          // Short PIN
	{"admin", "admin12345"},    // Very short PIN
	{"viewer", "viewer"},       // Viewer account
	{"admin", "12345678"},      // Long numeric password
	{"admin", "123456789"},     // Longer numeric password
	{"admin", "1234567890"},    // Longest numeric password
	{"admin", "12345678901"},   // Longest numeric password
	{"admin", "123456789012"},  // Longest numeric password
	{"admin", "1234567890123"}, // Longest numeric password
	{"admin", "Admin@123"},
	{"admin", "test!2345"},
	{"admin", "1qaz2wsx"},
	{"admin", "1qaz@WSX"},
	{"admin", "!@#$QWER"},
	{"admin", "p@ssword"},
	{"admin", "passw0rd"},
	{"admin", "p@ssw0rd"},
	{"admin", "AbcD@1234"},
	{"admin", "AbcD@12345"},
	{"admin", "AbcD@123456"},
	{"admin", "AbcD@1234567"},
	{"admin", "AbcD@12345678"},
	{"admin", "AbcD@123456789"},
	{"admin", "AbcD@1234567890"},
	{"admin", "Aa147258"},
	{"admin", "Aa147258963"},
	{"admin", "a88888888"},
	{"admin", "nc070928"},
	{"admin", "12345678a"},
	{"admin", "1q2w3e4r"},
	{"admin", "hik12345"},
	{"admin", "hik12345+"},
	{"admin", "Hik12345"},
	{"admin", "Hik12345+"},
	{"admin", "Hik12345-"},
	{"admin", "Hik12345_"},
	{"admin", "Hik12345."},
	{"admin", "Hik12345,"},
	{"admin", "hikang250"},
	{"admin", "hikang250+"},
	{"admin", "Hikang250"},
	{"admin", "Hikang250+"},
	{"admin", "Hikang250-"},
	{"admin", "Hikang250_"},
	{"admin", "Hikang250."},
	{"admin", "a1234567"},
	{"admin", "a12345678"},
	{"admin", "a1b2C3d4"},
	{"admin", "Huawei12#$"},
	{"admin", "Huawei12#$+"},
	{"admin", "Huawei12#$-"},
	{"admin", "Huawei12#$_"},
	{"admin", "Huawei12#$."},
	{"admin", "Huawei12#$,"},
	{"admin", "Huawei12#$"},
	{"admin", "hkdsb250"},
	{"admin", "Aa12345678"},
	{"admin", "woaidahua147258"},
	{"admin", "Aa159357"},
	{"admin", "qwer2468"},
	{"admin", "qtmdmm886"},
	{"admin", "hk135790"},
	{"admin", "adm45123"},
	{"admin", "qwert12345"},
	{"admin", "A987654321"},
	{"admin", "Dsbhk428"},
}

// Additional credentials loaded from file
var additionalCredentials [][]string

// Global variable to control silent mode for discovery operations
var discoverySilent bool

// SetCustomCredentials allows setting additional credentials from external source
func SetCustomCredentials(creds [][]string) {
	additionalCredentials = creds
}

// SetDiscoverySilent sets the silent mode for discovery operations
func SetDiscoverySilent(silent bool) {
	discoverySilent = silent
}

// conditionalPrintf prints to console only if not in silent mode
func conditionalPrintf(format string, args ...interface{}) {
	if !discoverySilent {
		fmt.Printf(format, args...)
	}
}

// getAllCredentials returns combined built-in and custom credentials
func getAllCredentials() [][]string {
	allCreds := make([][]string, len(weakCredentials))
	copy(allCreds, weakCredentials)
	allCreds = append(allCreds, additionalCredentials...)
	return allCreds
}

// StartDiscoveryAuto performs automatic discovery on all common private networks
func StartDiscoveryAuto(duration time.Duration) ([]Device, error) {
	commonNetworks := []string{
		"192.168.1.0/24",
		"192.168.0.0/24",
		"192.168.2.0/24",
		"10.0.0.0/16",
		"172.16.0.0/16",
	}

	return StartDiscoveryOnMultipleCIDRs(commonNetworks, duration)
}

// StartDiscoveryOnMultipleCIDRs performs discovery on multiple CIDR ranges
func StartDiscoveryOnMultipleCIDRs(cidrs []string, duration time.Duration) ([]Device, error) {
	var allDevices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, cidr := range cidrs {
		wg.Add(1)
		go func(network string) {
			defer wg.Done()
			devices, err := StartDiscoveryOnCIDR(network, duration)
			if err == nil {
				mu.Lock()
				allDevices = append(allDevices, devices...)
				mu.Unlock()
			}
		}(cidr)
	}

	wg.Wait()
	return removeDuplicateDevices(allDevices), nil
}

// StartDiscoveryOnCIDR performs hybrid discovery on a CIDR range
func StartDiscoveryOnCIDR(cidr string, duration time.Duration) ([]Device, error) {
	// Parse CIDR to determine if it's local or remote
	isLocal := isLocalNetwork(cidr)

	if isLocal {
		// Use WS-Discovery for local networks (faster)
		//fmt.Printf("[INFO] Using WS-Discovery for local network: %s\n", cidr)
		return LocalNetworkDiscovery(cidr, duration)
	} else {
		// Use TCP scanning for cross-network discovery
		//fmt.Printf("[INFO] Using TCP scanning for cross-network: %s\n", cidr)
		return CrossNetworkDiscovery(cidr, duration)
	}
}

// LocalNetworkDiscovery performs WS-Discovery within local broadcast domain
func LocalNetworkDiscovery(cidr string, duration time.Duration) ([]Device, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []Device{}, err
	}

	// Get local IP in this network
	localIP := getLocalIPInNetwork(ipNet)
	if localIP == "" {
		// No local interface in this network, fall back to TCP scanning
		return CrossNetworkDiscovery(cidr, duration)
	}

	// Use traditional WS-Discovery
	devices, err := discoverDevices(localIP, duration)
	if err != nil {
		return []Device{}, err
	}

	// Enhance device information
	for i := range devices {
		enhanceDeviceInfo(&devices[i])
	}

	return devices, nil
}

// CrossNetworkDiscovery performs true cross-network discovery using TCP port scanning
func CrossNetworkDiscovery(cidr string, duration time.Duration) ([]Device, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []Device{}, err
	}

	var allDevices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Get all IPs in the CIDR range
	ips := getIPsFromCIDR(ipNet)

	// Create a channel to limit concurrent scans (reduced for stability)
	maxConcurrent := 20
	sem := make(chan struct{}, maxConcurrent)

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			device, found := scanOnvifDevice(ipAddr, duration)
			if found {
				mu.Lock()
				allDevices = append(allDevices, device)
				mu.Unlock()
			}
		}(ip.String())
	}

	wg.Wait()
	return removeDuplicateDevices(allDevices), nil
}

// scanOnvifDevice scans a single IP for ONVIF services
func scanOnvifDevice(ip string, timeout time.Duration) (Device, bool) {
	// Try WS-Discovery first (for devices that support unicast)
	devices, err := discoverDevicesUnicast(ip+":3702", timeout/2)
	if err == nil && len(devices) > 0 {
		device := devices[0]
		enhanceDeviceInfo(&device)
		conditionalPrintf("[SUCCESS] Found device via unicast WS-Discovery: %s (Manufacturer: %s, Model: %s)\n",
			device.Name, device.Manufacturer, device.Model)
		return device, true
	}

	// Fall back to HTTP-based detection
	for _, port := range onvifPorts {
		//fmt.Printf("[DEBUG] Trying unicast WS-Discovery to %s:%d\n", ip, port)

		// Quick TCP connection test
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout/10)
		if err != nil {
			continue
		}
		conn.Close()

		// Try HTTP detection with enhanced device info extraction
		device, found := detectOnvifByHTTP(ip, port, timeout/5)
		if found {
			enhanceDeviceInfoCrossNetwork(&device, ip, port)
			conditionalPrintf("[SUCCESS] Found device via HTTP scanning: %s at %s:%d\n", device.Name, ip, port)
			return device, true
		}
	}

	//fmt.Printf("[DEBUG] No ONVIF device found on %s\n", ip)
	return Device{}, false
}

// detectOnvifByHTTP tries to detect ONVIF device via HTTP
func detectOnvifByHTTP(ip string, port int, timeout time.Duration) (Device, bool) {
	client := &http.Client{Timeout: timeout}

	for _, path := range onvifPaths {
		url := fmt.Sprintf("http://%s:%d%s", ip, port, path)

		// Try GetCapabilities request
		soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
		<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
			<s:Body>
				<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
					<tds:Category>All</tds:Category>
				</tds:GetCapabilities>
			</s:Body>
		</s:Envelope>`

		req, _ := http.NewRequest("POST", url, strings.NewReader(soapRequest))
		req.Header.Set("Content-Type", "application/soap+xml")
		req.Header.Set("SOAPAction", "http://www.onvif.org/ver10/device/wsdl/GetCapabilities")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := ioutil.ReadAll(resp.Body)
			if strings.Contains(string(body), "onvif") || strings.Contains(string(body), "ONVIF") {
				device := Device{
					ID:    fmt.Sprintf("tcp-detected-%s-%d", ip, port),
					Name:  ip,
					XAddr: url,
					IP:    ip,
					Port:  port,
				}
				return device, true
			}
		}
	}

	return Device{}, false
}

// discoverDevicesUnicast performs unicast WS-Discovery
func discoverDevicesUnicast(targetIP string, duration time.Duration) ([]Device, error) {
	//fmt.Printf("[DEBUG] Trying unicast WS-Discovery to %s\n", targetIP)

	// Create WS-Discovery request
	requestID := "uuid:" + uuid.New().String()

	request := `<?xml version="1.0" encoding="UTF-8"?>
				<s:Envelope
					xmlns:s="http://www.w3.org/2003/05/soap-envelope"
					xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
					<s:Header>
						<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
						<a:MessageID>` + requestID + `</a:MessageID>
						<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
						<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
					</s:Header>
					<s:Body>
						<Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
							<d:Types xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dp0="http://www.onvif.org/ver10/network/wsdl">dp0:NetworkVideoTransmitter</d:Types>
						</Probe>
					</s:Body>
				</s:Envelope>`

	// Clean request
	request = regexp.MustCompile(`>\s+<`).ReplaceAllString(request, "><")
	request = regexp.MustCompile(`\s+`).ReplaceAllString(request, " ")

	// Create UDP connection
	conn, err := net.Dial("udp", targetIP)
	if err != nil {
		return []Device{}, err
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(duration))

	// Send request
	_, err = conn.Write([]byte(request))
	if err != nil {
		return []Device{}, err
	}

	// Read response
	buffer := make([]byte, 10*1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return []Device{}, err
	}

	// Parse response
	device, err := readDiscoveryResponse(requestID, buffer[:n])
	if err != nil {
		return []Device{}, err
	}

	//fmt.Printf("[SUCCESS] Unicast WS-Discovery successful on %s\n", targetIP)
	return []Device{device}, nil
}

// StartDiscoveryOn performs discovery on a specific interface
func StartDiscoveryOn(interfaceName string, duration time.Duration) ([]Device, error) {
	itf, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return []Device{}, err
	}

	item, _ := itf.Addrs()
	var ip net.IP
	for _, addr := range item {
		switch v := addr.(type) {
		case *net.IPNet:
			if !v.IP.IsLoopback() {
				if v.IP.To4() != nil {
					ip = v.IP
				}
			}
		}
	}

	if ip == nil {
		return []Device{}, err
	}

	devices, err := discoverDevices(ip.String(), duration)
	for i := range devices {
		enhanceDeviceInfo(&devices[i])
	}

	return devices, err
}

// StartDiscovery performs discovery on all interfaces
func StartDiscovery(interfaceName string, duration time.Duration) ([]Device, error) {
	if interfaceName != "" {
		return StartDiscoveryOn(interfaceName, duration)
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []Device{}, err
	}

	var ipAddrs []string
	for _, addr := range addrs {
		ipAddr, ok := addr.(*net.IPNet)
		if ok && !ipAddr.IP.IsLoopback() && ipAddr.IP.To4() != nil {
			ipAddrs = append(ipAddrs, ipAddr.IP.String())
		}
	}

	var discoveryResults []Device
	for _, ipAddr := range ipAddrs {
		devices, err := discoverDevices(ipAddr, duration)
		if err != nil {
			return []Device{}, err
		}

		for i := range devices {
			enhanceDeviceInfo(&devices[i])
		}

		discoveryResults = append(discoveryResults, devices...)
	}

	return discoveryResults, nil
}

// discoverDevices performs traditional WS-Discovery multicast
func discoverDevices(ipAddr string, duration time.Duration) ([]Device, error) {
	requestID := "uuid:" + uuid.New().String()

	request := `<?xml version="1.0" encoding="UTF-8"?>
				<s:Envelope
					xmlns:s="http://www.w3.org/2003/05/soap-envelope"
					xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
					<s:Header>
						<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
						<a:MessageID>` + requestID + `</a:MessageID>
						<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
						<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
					</s:Header>
					<s:Body>
						<Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
							<d:Types xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dp0="http://www.onvif.org/ver10/network/wsdl">dp0:NetworkVideoTransmitter</d:Types>
						</Probe>
					</s:Body>
				</s:Envelope>`

	request = regexp.MustCompile(`>\s+<`).ReplaceAllString(request, "><")
	request = regexp.MustCompile(`\s+`).ReplaceAllString(request, " ")

	localAddress, err := net.ResolveUDPAddr("udp4", ipAddr+":0")
	if err != nil {
		return []Device{}, err
	}

	multicastAddress, err := net.ResolveUDPAddr("udp4", "239.255.255.250:3702")
	if err != nil {
		return []Device{}, err
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		return []Device{}, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(duration))
	if err != nil {
		return []Device{}, err
	}

	_, err = conn.WriteToUDP([]byte(request), multicastAddress)
	if err != nil {
		return []Device{}, err
	}

	discoveryResults := make([]Device, 0)

	for {
		buffer := make([]byte, 10*1024)
		_, _, err = conn.ReadFromUDP(buffer)

		if err != nil {
			if udpErr, ok := err.(net.Error); ok && udpErr.Timeout() {
				break
			} else {
				return discoveryResults, err
			}
		}

		device, err := readDiscoveryResponse(requestID, buffer)
		if err != nil && err != errWrongDiscoveryResponse {
			return discoveryResults, err
		}

		if err == nil {
			discoveryResults = append(discoveryResults, device)
		}
	}

	return discoveryResults, nil
}

// readDiscoveryResponse reads and parses WS-Discovery response
func readDiscoveryResponse(messageID string, buffer []byte) (Device, error) {
	glog.V(2).Infof("Discover response: %s", string(buffer))

	result := Device{}

	mapXML, err := mxj.NewMapXml(buffer)
	if err != nil {
		glog.Warningf("Parse response error %v", err)
		return result, err
	}

	responseMessageID, err := mapXML.ValueForPath("Envelope.Header.RelatesTo")
	if err != nil {
		glog.Warningf("Parse message id error %v", err)
		return result, err
	}

	if responseMessageMap, ok := responseMessageID.(map[string]interface{}); ok {
		responseMessage := responseMessageMap["#text"].(string)
		if responseMessage != messageID {
			return result, errWrongDiscoveryResponse
		}
	} else {
		if responseMessageID != messageID {
			return result, errWrongDiscoveryResponse
		}
	}

	// Get device's ID and clean it
	deviceID, _ := mapXML.ValueForPathString("Envelope.Body.ProbeMatches.ProbeMatch.EndpointReference.Address")
	// Handle different UUID formats from different manufacturers
	// Hikvision: urn:uuid:0a940000-d700-11b5-84bd-98df82531003
	// Dahua: uuid:0bed4837-89e7-d669-c76b-8b6e4a2989e7
	deviceID = strings.Replace(deviceID, "urn:uuid:", "", 1)
	deviceID = strings.Replace(deviceID, "uuid:", "", 1)
	glog.V(2).Infof("Discover device id: %s", deviceID)

	// Get raw scopes for enhanced parsing
	scopes, _ := mapXML.ValueForPathString("Envelope.Body.ProbeMatches.ProbeMatch.Scopes")
	glog.V(2).Infof("Raw scopes from WS-Discovery: %s", scopes)

	// Parse enhanced device information from scopes
	deviceName, manufacturer, model, hardwareID, macAddress := parseOnvifScopes(scopes)

	// Get device's xAddrs
	xAddrs, _ := mapXML.ValueForPathString("Envelope.Body.ProbeMatches.ProbeMatch.XAddrs")
	listXAddr := strings.Split(xAddrs, " ")
	glog.V(2).Infof("Discover address: %s", xAddrs)

	if len(listXAddr) == 0 {
		glog.Warning("Discover address len 0")
		return result, errors.New("Device does not have any xAddr ")
	}

	// Extract IP and port from XAddr
	ip, port := extractIPPortFromXAddr(listXAddr[0])

	// Finalize result with enhanced information
	result.ID = deviceID
	result.Name = deviceName
	result.XAddr = listXAddr[0]
	result.IP = ip
	result.Port = port
	result.Manufacturer = manufacturer
	result.Model = model
	result.HardwareID = hardwareID
	result.MACAddress = macAddress

	glog.V(2).Infof("After parsing WS-Discovery scopes - Manufacturer: %s, Model: %s, MAC: %s, Hardware: %s",
		manufacturer, model, macAddress, hardwareID)

	conditionalPrintf("[SUCCESS] WS-Discovery device parsed - Name: %s, Manufacturer: %s, Model: %s, MAC: %s\n",
		deviceName, manufacturer, model, macAddress)

	return result, nil
}

// Helper functions

func parseOnvifScopes(scopes string) (name, manufacturer, model, hardwareID, macAddress string) {
	for _, scope := range strings.Split(scopes, " ") {
		scope = strings.TrimSpace(scope)
		if strings.HasPrefix(scope, "onvif://www.onvif.org/name/") {
			name = strings.Replace(scope, "onvif://www.onvif.org/name/", "", 1)
			name = strings.Replace(name, "%20", " ", -1)
			name = strings.Replace(name, "_", " ", -1)
		} else if strings.HasPrefix(scope, "onvif://www.onvif.org/hardware/") {
			model = strings.Replace(scope, "onvif://www.onvif.org/hardware/", "", 1)
			hardwareID = model
		} else if strings.HasPrefix(scope, "onvif://www.onvif.org/MAC/") {
			macAddress = strings.Replace(scope, "onvif://www.onvif.org/MAC/", "", 1)
		}
	}

	// Extract manufacturer from device name if available
	if name != "" {
		parts := strings.Fields(name)
		if len(parts) > 0 {
			// Common manufacturer names
			firstWord := strings.ToUpper(parts[0])
			if firstWord == "HIKVISION" || firstWord == "DAHUA" || firstWord == "AXIS" ||
				firstWord == "SONY" || firstWord == "PANASONIC" || firstWord == "BOSCH" {
				manufacturer = parts[0]
			}
		}
	}

	return
}

func extractIPPortFromXAddr(xaddr string) (string, int) {
	// Parse URL to extract IP and port
	if strings.HasPrefix(xaddr, "http://") {
		xaddr = strings.TrimPrefix(xaddr, "http://")
		parts := strings.Split(xaddr, "/")
		if len(parts) > 0 {
			hostPort := parts[0]
			if strings.Contains(hostPort, ":") {
				hostParts := strings.Split(hostPort, ":")
				if len(hostParts) == 2 {
					port := 80
					fmt.Sscanf(hostParts[1], "%d", &port)
					return hostParts[0], port
				}
			}
			return hostPort, 80
		}
	}
	return "", 80
}

func isLocalNetwork(cidr string) bool {
	// Get local network interfaces
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	_, targetNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// Check if any local interface is in the target network
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			if targetNet.Contains(ipNet.IP) {
				return true
			}
		}
	}

	return false
}

func getLocalIPInNetwork(targetNet *net.IPNet) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			if targetNet.Contains(ipNet.IP) {
				return ipNet.IP.String()
			}
		}
	}

	return ""
}

func getIPsFromCIDR(ipNet *net.IPNet) []net.IP {
	var ips []net.IP

	ip := ipNet.IP.Mask(ipNet.Mask)
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, net.ParseIP(ip.String()))
	}

	// Remove network and broadcast addresses for /24 networks
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func removeDuplicateDevices(devices []Device) []Device {
	keys := make(map[string]bool)
	var result []Device

	for _, device := range devices {
		key := device.XAddr
		if !keys[key] {
			keys[key] = true
			result = append(result, device)
		}
	}

	return result
}

func enhanceDeviceInfo(device *Device) {
	// Initialize security status
	device.AuthStatus = "auth_required"
	device.WeakPassword = false

	// First, try weak credential detection
	testWeakCredentials(device)

	// Make additional SOAP calls to get detailed device information
	// Try multiple approaches to gather maximum information

	// Try to get device information details
	tryGetDeviceInformationDetails(device)

	// Try to get raw scopes from the device
	tryGetRawScopes(device)

	// Try to get MAC address from network interfaces
	tryGetMACAddress(device)

	// Try to get hostname information
	tryGetHostname(device)

	// Test RTSP authentication on the same device
	if device.IP != "" {
		conditionalPrintf("[INFO] Testing RTSP capabilities for discovered device %s\n", device.IP)
		testRTSPOnDiscoveredDevice(device)

		// Cross-protocol credential sharing
		handleCredentialSharing(device)
	}

	// Ensure we have basic info
	if device.Name == "" && device.Model != "" {
		device.Name = device.Model
	}

	// Try to extract manufacturer from name if not already set
	if device.Manufacturer == "" && device.Name != "" {
		device.Manufacturer = extractManufacturerFromName(device.Name)
	}
}

// tryGetDeviceInformationDetails attempts to get detailed device information via SOAP
func tryGetDeviceInformationDetails(device *Device) {
	if device.XAddr == "" {
		return
	}

	// Create GetDeviceInformation SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
	<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
		<s:Body>
			<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
		</s:Body>
	</s:Envelope>`

	response, err := makeSOAPRequest(device.XAddr, soapRequest, "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation")
	if err != nil {
		glog.V(2).Infof("Failed to get device information from %s: %v", device.XAddr, err)
		return
	}

	// Parse response to extract device information
	if mapXML, err := mxj.NewMapXml([]byte(response)); err == nil {
		if manufacturer, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.Manufacturer"); manufacturer != "" {
			device.Manufacturer = manufacturer
		}
		if model, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.Model"); model != "" {
			device.Model = model
		}
		if serialNumber, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.SerialNumber"); serialNumber != "" {
			device.SerialNumber = serialNumber
		}
		if hardwareId, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.HardwareId"); hardwareId != "" {
			device.HardwareID = hardwareId
		}
		if firmwareVersion, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.FirmwareVersion"); firmwareVersion != "" {
			device.FirmwareVersion = firmwareVersion
		}

		glog.V(2).Infof("Enhanced device info from GetDeviceInformation - Manufacturer: %s, Model: %s, Serial: %s",
			device.Manufacturer, device.Model, device.SerialNumber)
	}
}

// tryGetDeviceInformationDetailsAuth attempts to get detailed device information via authenticated SOAP
func tryGetDeviceInformationDetailsAuth(device *Device, username, password string) {
	if device.XAddr == "" {
		return
	}

	// Create GetDeviceInformation SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
	<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
		<s:Body>
			<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
		</s:Body>
	</s:Envelope>`

	response, err := makeAuthenticatedSOAPRequest(device.XAddr, soapRequest, "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation", username, password)
	if err != nil {
		glog.V(2).Infof("Failed to get authenticated device information from %s: %v", device.XAddr, err)
		return
	}

	// Parse response to extract device information
	if mapXML, err := mxj.NewMapXml([]byte(response)); err == nil {
		if manufacturer, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.Manufacturer"); manufacturer != "" {
			device.Manufacturer = manufacturer
		}
		if model, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.Model"); model != "" {
			device.Model = model
		}
		if serialNumber, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.SerialNumber"); serialNumber != "" {
			device.SerialNumber = serialNumber
		}
		if hardwareId, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.HardwareId"); hardwareId != "" {
			device.HardwareID = hardwareId
		}
		if firmwareVersion, _ := mapXML.ValueForPathString("Envelope.Body.GetDeviceInformationResponse.FirmwareVersion"); firmwareVersion != "" {
			device.FirmwareVersion = firmwareVersion
		}

		glog.V(2).Infof("Enhanced device info from authenticated GetDeviceInformation - Manufacturer: %s, Model: %s, Serial: %s",
			device.Manufacturer, device.Model, device.SerialNumber)
		conditionalPrintf("[SUCCESS] Retrieved detailed info: %s %s (Serial: %s, FW: %s)\n",
			device.Manufacturer, device.Model, device.SerialNumber, device.FirmwareVersion)
	}
}

// tryGetRawScopes attempts to get raw scopes from the device
func tryGetRawScopes(device *Device) {
	if device.XAddr == "" {
		return
	}

	// Create GetScopes SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
	<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
		<s:Body>
			<tds:GetScopes xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
		</s:Body>
	</s:Envelope>`

	response, err := makeSOAPRequest(device.XAddr, soapRequest, "http://www.onvif.org/ver10/device/wsdl/GetScopes")
	if err != nil {
		glog.V(2).Infof("Failed to get scopes from %s: %v", device.XAddr, err)
		return
	}

	// Parse response to extract scopes
	if mapXML, err := mxj.NewMapXml([]byte(response)); err == nil {
		// Try to extract scopes array
		if scopesData, err := mapXML.ValueForPath("Envelope.Body.GetScopesResponse.Scopes"); err == nil {
			var scopes []string

			// Handle both single scope and array of scopes
			switch v := scopesData.(type) {
			case []interface{}:
				for _, scope := range v {
					if scopeMap, ok := scope.(map[string]interface{}); ok {
						if scopeItem, ok := scopeMap["ScopeItem"].(string); ok {
							scopes = append(scopes, scopeItem)
						}
					}
				}
			case map[string]interface{}:
				if scopeItem, ok := v["ScopeItem"].(string); ok {
					scopes = append(scopes, scopeItem)
				}
			}

			device.Scopes = scopes

			// Parse individual scopes for additional information
			for _, scope := range scopes {
				parseScopeInformation(device, scope)
			}

			glog.V(2).Infof("Enhanced device info from GetScopes - found %d scopes", len(scopes))
		}
	}
}

// tryGetMACAddress attempts to get MAC address from network interfaces
func tryGetMACAddress(device *Device) {
	if device.XAddr == "" || device.MACAddress != "" {
		return
	}

	// Create GetNetworkInterfaces SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
	<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
		<s:Body>
			<tds:GetNetworkInterfaces xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
		</s:Body>
	</s:Envelope>`

	response, err := makeSOAPRequest(device.XAddr, soapRequest, "http://www.onvif.org/ver10/device/wsdl/GetNetworkInterfaces")
	if err != nil {
		glog.V(2).Infof("Failed to get network interfaces from %s: %v", device.XAddr, err)
		return
	}

	// Parse response to extract MAC address
	if mapXML, err := mxj.NewMapXml([]byte(response)); err == nil {
		if macAddr, _ := mapXML.ValueForPathString("Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.Info.HwAddress"); macAddr != "" {
			device.MACAddress = macAddr
			glog.V(2).Infof("Enhanced device info from GetNetworkInterfaces - MAC: %s", device.MACAddress)
		}
	}
}

// tryGetMACAddressAuth attempts to get MAC address from network interfaces using authentication
func tryGetMACAddressAuth(device *Device, username, password string) {
	if device.XAddr == "" || device.MACAddress != "" {
		return
	}

	// Create GetNetworkInterfaces SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
	<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
		<s:Body>
			<tds:GetNetworkInterfaces xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
		</s:Body>
	</s:Envelope>`

	response, err := makeAuthenticatedSOAPRequest(device.XAddr, soapRequest, "http://www.onvif.org/ver10/device/wsdl/GetNetworkInterfaces", username, password)
	if err != nil {
		glog.V(2).Infof("Failed to get network interfaces with auth from %s: %v", device.XAddr, err)
		return
	}

	// Parse response to extract MAC address
	if mapXML, err := mxj.NewMapXml([]byte(response)); err == nil {
		// Try multiple possible paths for MAC address based on common ONVIF implementations
		macPaths := []string{
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.Info.HwAddress",
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.0.Info.HwAddress",
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.Info.0.HwAddress",
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.Info.HardwareAddress",
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.HwAddress",
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.0.HwAddress",
			// Hikvision specific paths
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.Info.MACAddress",
			"Envelope.Body.GetNetworkInterfacesResponse.NetworkInterfaces.MACAddress",
		}

		for _, path := range macPaths {
			if macAddr, _ := mapXML.ValueForPathString(path); macAddr != "" {
				device.MACAddress = macAddr
				glog.V(2).Infof("Enhanced device info from authenticated GetNetworkInterfaces - MAC: %s (path: %s)", device.MACAddress, path)
				return
			}
		}

		// Log full response for debugging if verbose logging is enabled
		glog.V(3).Infof("GetNetworkInterfaces response for debugging: %s", response)
		glog.V(2).Infof("MAC address not found in any known paths for %s", device.XAddr)
	}
}

// tryGetHostname attempts to get hostname information
func tryGetHostname(device *Device) {
	if device.XAddr == "" {
		return
	}

	// Create GetHostname SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
	<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
		<s:Body>
			<tds:GetHostname xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
		</s:Body>
	</s:Envelope>`

	response, err := makeSOAPRequest(device.XAddr, soapRequest, "http://www.onvif.org/ver10/device/wsdl/GetHostname")
	if err != nil {
		glog.V(2).Infof("Failed to get hostname from %s: %v", device.XAddr, err)
		return
	}

	// Parse response to extract hostname
	if mapXML, err := mxj.NewMapXml([]byte(response)); err == nil {
		if hostname, _ := mapXML.ValueForPathString("Envelope.Body.GetHostnameResponse.HostnameInformation.Name"); hostname != "" {
			if device.Name == "" {
				device.Name = hostname
			}
			glog.V(2).Infof("Enhanced device info from GetHostname - Hostname: %s", hostname)
		}
	}
}

// parseScopeInformation parses individual ONVIF scope strings to extract information
func parseScopeInformation(device *Device, scope string) {
	scope = strings.TrimSpace(scope)

	if strings.HasPrefix(scope, "onvif://www.onvif.org/name/") {
		name := strings.Replace(scope, "onvif://www.onvif.org/name/", "", 1)
		name = strings.Replace(name, "%20", " ", -1)
		name = strings.Replace(name, "_", " ", -1)
		if device.Name == "" {
			device.Name = name
		}
	} else if strings.HasPrefix(scope, "onvif://www.onvif.org/hardware/") {
		hardware := strings.Replace(scope, "onvif://www.onvif.org/hardware/", "", 1)
		if device.HardwareID == "" {
			device.HardwareID = hardware
		}
		if device.Model == "" {
			device.Model = hardware
		}
	} else if strings.HasPrefix(scope, "onvif://www.onvif.org/MAC/") {
		mac := strings.Replace(scope, "onvif://www.onvif.org/MAC/", "", 1)
		if device.MACAddress == "" {
			device.MACAddress = mac
		}
	} else if strings.HasPrefix(scope, "onvif://www.onvif.org/location/") {
		location := strings.Replace(scope, "onvif://www.onvif.org/location/", "", 1)
		location = strings.Replace(location, "city/", "", 1)
		location = strings.Replace(location, "country/", "", 1)
		if device.Location == "" {
			device.Location = location
		}
	} else if strings.HasPrefix(scope, "onvif://www.onvif.org/Profile/") {
		profile := strings.Replace(scope, "onvif://www.onvif.org/Profile/", "", 1)
		if device.Capabilities == nil {
			device.Capabilities = make(map[string]bool)
		}
		device.Capabilities[profile] = true
	} else if strings.HasPrefix(scope, "onvif://www.onvif.org/type/") {
		deviceType := strings.Replace(scope, "onvif://www.onvif.org/type/", "", 1)
		if device.Capabilities == nil {
			device.Capabilities = make(map[string]bool)
		}
		device.Capabilities[deviceType] = true
	}
}

// makeSOAPRequest makes a SOAP request to the specified endpoint
func makeSOAPRequest(endpoint, soapBody, soapAction string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(soapBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", soapAction)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// makeAuthenticatedSOAPRequest makes a SOAP request with digest authentication
func makeAuthenticatedSOAPRequest(endpoint, soapBody, soapAction, username, password string) (string, error) {
	// Create digest transport with credentials
	transport := onvifDigest.NewTransport(username, password)
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Create request with reusable body
	bodyData := []byte(soapBody)
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(bodyData))
	if err != nil {
		return "", err
	}
	req.ContentLength = int64(len(bodyData))

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", soapAction)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// extractManufacturerFromName tries to extract manufacturer from device name
func extractManufacturerFromName(name string) string {
	if name == "" {
		return ""
	}

	parts := strings.Fields(strings.ToUpper(name))
	if len(parts) > 0 {
		firstWord := parts[0]
		// Common ONVIF manufacturer names
		manufacturers := []string{
			"HIKVISION", "DAHUA", "AXIS", "SONY", "PANASONIC", "BOSCH",
			"SAMSUNG", "AVIGILON", "FLIR", "HANWHA", "VIVOTEK", "GEOVISION",
			"PELCO", "HONEYWELL", "UNIVIEW", "TIANDY", "ZKTECO", "KEDACOM",
		}

		for _, manufacturer := range manufacturers {
			if strings.Contains(firstWord, manufacturer) {
				return manufacturer
			}
		}
	}

	return ""
}

// enhanceDeviceInfoCrossNetwork enhances device information for cross-network discovered devices
func enhanceDeviceInfoCrossNetwork(device *Device, ip string, port int) {
	// For cross-network devices, try multiple ONVIF service endpoints
	baseURLs := []string{
		fmt.Sprintf("http://%s:%d/onvif/device_service", ip, port),
		fmt.Sprintf("http://%s:%d/onvif/Device", ip, port),
		fmt.Sprintf("http://%s:%d/device_service", ip, port),
		fmt.Sprintf("http://%s:%d/Device", ip, port),
	}

	// Try each endpoint until we find one that works
	for _, url := range baseURLs {
		device.XAddr = url

		// Try to get device capabilities first
		if tryGetCapabilitiesCrossNetwork(device) {
			break
		}
	}

	// Now try to enhance with detailed information
	enhanceDeviceInfo(device)

	// Ensure IP and port are set
	device.IP = ip
	device.Port = port

	// If we still don't have a name, create a default one
	if device.Name == "" {
		if device.Model != "" {
			device.Name = fmt.Sprintf("%s %s", device.Manufacturer, device.Model)
		} else {
			device.Name = fmt.Sprintf(ip)
		}
	}
}

// tryGetCapabilitiesCrossNetwork tries to get capabilities to verify ONVIF endpoint
func tryGetCapabilitiesCrossNetwork(device *Device) bool {
	if device.XAddr == "" {
		return false
	}

	// Create GetCapabilities SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
	<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
		<s:Body>
			<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
				<tds:Category>All</tds:Category>
			</tds:GetCapabilities>
		</s:Body>
	</s:Envelope>`

	response, err := makeSOAPRequest(device.XAddr, soapRequest, "http://www.onvif.org/ver10/device/wsdl/GetCapabilities")
	if err != nil {
		return false
	}

	// Parse response to extract capabilities and service endpoints
	if mapXML, err := mxj.NewMapXml([]byte(response)); err == nil {
		// Check if this is a valid ONVIF response
		if _, err := mapXML.ValueForPath("Envelope.Body.GetCapabilitiesResponse"); err == nil {
			// Parse service endpoints
			if device.Services == nil {
				device.Services = make(map[string]string)
			}

			// Extract various service endpoints
			if mediaXAddr, _ := mapXML.ValueForPathString("Envelope.Body.GetCapabilitiesResponse.Capabilities.Media.XAddr"); mediaXAddr != "" {
				device.Services["Media"] = mediaXAddr
			}
			if ptzXAddr, _ := mapXML.ValueForPathString("Envelope.Body.GetCapabilitiesResponse.Capabilities.PTZ.XAddr"); ptzXAddr != "" {
				device.Services["PTZ"] = ptzXAddr
			}
			if eventsXAddr, _ := mapXML.ValueForPathString("Envelope.Body.GetCapabilitiesResponse.Capabilities.Events.XAddr"); eventsXAddr != "" {
				device.Services["Events"] = eventsXAddr
			}
			if imagingXAddr, _ := mapXML.ValueForPathString("Envelope.Body.GetCapabilitiesResponse.Capabilities.Imaging.XAddr"); imagingXAddr != "" {
				device.Services["Imaging"] = imagingXAddr
			}

			glog.V(2).Infof("Successfully verified ONVIF endpoint at %s", device.XAddr)
			return true
		}
	}

	return false
}

// testWeakCredentials attempts to authenticate with common weak credentials
func testWeakCredentials(device *Device) {
	if device.XAddr == "" {
		device.AuthStatus = "auth_failed"
		return
	}

	//fmt.Printf("[SECURITY] Testing weak credentials for %s...\n", device.XAddr)

	// Get all credentials (built-in + custom)
	allCredentials := getAllCredentials()
	//fmt.Printf("[SECURITY] Testing %d credential combinations...\n", len(allCredentials))

	// Test each credential pair
	for _, creds := range allCredentials {
		username := creds[0]
		password := creds[1]

		credStr := fmt.Sprintf("%s:%s", username, password)

		//fmt.Printf("[SECURITY] Trying credentials: %s\n", credStr)

		// Test authentication by attempting GetDeviceInformation
		if testAuthentication(device.XAddr, username, password) {
			device.User = username
			device.Password = password
			device.WorkingCreds = credStr

			if isWeakCredential(username, password) {
				device.AuthStatus = "weak_auth"
				device.WeakPassword = true
				conditionalPrintf("[WARNING] Weak credentials found: %s for device %s\n", credStr, device.XAddr)
			} else {
				device.AuthStatus = "no_auth"
				conditionalPrintf("[INFO] No authentication required for device %s\n", device.XAddr)
			}

			// Now that we have working credentials, get detailed device information
			conditionalPrintf("[INFO] Fetching detailed device information with authenticated access...\n")
			tryGetDeviceInformationDetailsAuth(device, username, password)
			tryGetMACAddressAuth(device, username, password)

			return
		}

		// Add small delay between credential attempts to avoid overwhelming devices
		time.Sleep(200 * time.Millisecond)
	}

	device.AuthStatus = "auth_required"
	conditionalPrintf("[INFO] All weak credentials failed for %s\n", device.XAddr)
}

// testAuthentication tests if given credentials work for ONVIF device
func testAuthentication(xaddr, username, password string) bool {
	// Add debug logging for credential testing
	credStr := fmt.Sprintf("%s:%s", username, password)

	// Create digest transport with credentials
	transport := onvifDigest.NewTransport(username, password)
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // Increased timeout for slow devices
	}

	// Create GetDeviceInformation SOAP request
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Body>
		<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
	</s:Body>
</s:Envelope>`

	// Create request with body that can be reused for digest auth
	bodyData := []byte(soapRequest)
	req, err := http.NewRequest("POST", xaddr, bytes.NewReader(bodyData))
	if err != nil {
		conditionalPrintf("[DEBUG] Failed to create request for %s: %v\n", credStr, err)
		return false
	}
	req.ContentLength = int64(len(bodyData))

	// Debug: log SOAP request length
	conditionalPrintf("[DEBUG] SOAP request length for %s: %d bytes\n", credStr, len(soapRequest))

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", "")

	resp, err := client.Do(req)
	if err != nil {
		conditionalPrintf("[DEBUG] HTTP request failed for %s: %v\n", credStr, err)
		return false
	}
	defer resp.Body.Close()

	// Log the response for debugging
	conditionalPrintf("[DEBUG] Credential %s returned HTTP %d\n", credStr, resp.StatusCode)

	// If we get a 401, it means credentials are wrong
	// If we get a 200, credentials worked
	// Other status codes might indicate other issues
	if resp.StatusCode == 401 {
		conditionalPrintf("[DEBUG] Authentication failed (401) for %s\n", credStr)
		return false
	} else if resp.StatusCode == 200 {
		conditionalPrintf("[SUCCESS] Authentication succeeded for %s\n", credStr)
		return true
	} else {
		// Log other response codes for debugging
		body, _ := ioutil.ReadAll(resp.Body)
		maxLen := 200
		if len(body) < maxLen {
			maxLen = len(body)
		}
		conditionalPrintf("[DEBUG] Unexpected response %d for %s, body: %s\n", resp.StatusCode, credStr, string(body[:maxLen]))
		return resp.StatusCode == 200
	}
}

// isWeakCredential determines if a credential pair is considered weak
func isWeakCredential(username, password string) bool {
	// Empty password is always weak
	if password == "" {
		return true
	}

	// Same username and password is weak
	if username == password {
		return true
	}

	// Check if this combination is in our weak credentials list
	for _, creds := range weakCredentials {
		if creds[0] == username && creds[1] == password {
			return true
		}
	}

	// Short passwords are weak
	if len(password) < 6 {
		return true
	}

	return false
}

// retryOnvifWithRTSPCreds attempts ONVIF authentication using RTSP credentials
func retryOnvifWithRTSPCreds(device *Device) {
	if device.XAddr == "" || device.RTSPWorkingCreds == "" {
		return
	}

	// Parse RTSP credentials
	parts := strings.Split(device.RTSPWorkingCreds, ":")
	if len(parts) != 2 {
		return
	}
	username := parts[0]
	password := parts[1]

	// Test ONVIF authentication with RTSP credentials
	if testAuthentication(device.XAddr, username, password) {
		device.User = username
		device.Password = password
		device.WorkingCreds = device.RTSPWorkingCreds

		if isWeakCredential(username, password) {
			device.AuthStatus = "weak_auth"
			device.WeakPassword = true
			conditionalPrintf("[SUCCESS] ONVIF authentication succeeded with RTSP credentials: %s for device %s\n", device.RTSPWorkingCreds, device.XAddr)
		} else {
			device.AuthStatus = "no_auth"
			conditionalPrintf("[SUCCESS] ONVIF no authentication required (verified with RTSP creds) for device %s\n", device.XAddr)
		}

		// Now that we have working ONVIF credentials, try to get more detailed device information
		conditionalPrintf("[INFO] Fetching detailed device information with authenticated access...\n")
		tryGetDeviceInformationDetailsAuth(device, username, password)
		tryGetMACAddressAuth(device, username, password)
		// For now, just try the regular versions since we have working credentials
		// TODO: Implement authenticated versions if needed
		tryGetRawScopes(device)
		tryGetHostname(device)
	}
}

// handleCredentialSharing handles bidirectional credential sharing between ONVIF and RTSP
func handleCredentialSharing(device *Device) {
	// Case 1: ONVIF found credentials, RTSP needs testing
	if device.WorkingCreds != "" && device.RTSPAuthStatus == "unknown" {
		conditionalPrintf("[INFO] Testing RTSP with ONVIF credentials: %s\n", device.WorkingCreds)
		retryRTSPWithOnvifCreds(device)
	}

	// Case 2: RTSP found credentials, ONVIF needs authentication
	if device.RTSPWorkingCreds != "" && device.AuthStatus == "auth_required" {
		conditionalPrintf("[INFO] Retrying ONVIF authentication with RTSP credentials: %s\n", device.RTSPWorkingCreds)
		retryOnvifWithRTSPCreds(device)
	}

	// Case 3: Both protocols found different credentials - log for analysis
	if device.WorkingCreds != "" && device.RTSPWorkingCreds != "" && device.WorkingCreds != device.RTSPWorkingCreds {
		conditionalPrintf("[INFO] Different credentials found - ONVIF: %s, RTSP: %s\n", device.WorkingCreds, device.RTSPWorkingCreds)
	}
}

// retryRTSPWithOnvifCreds attempts RTSP authentication using ONVIF credentials
func retryRTSPWithOnvifCreds(device *Device) {
	if device.WorkingCreds == "" || device.IP == "" {
		return
	}

	// Parse ONVIF credentials
	parts := strings.Split(device.WorkingCreds, ":")
	if len(parts) != 2 {
		return
	}
	username := parts[0]
	password := parts[1]

	// Test common RTSP ports with ONVIF credentials
	rtspPorts := []int{554, 8554, 1935, 8935}

	for _, port := range rtspPorts {
		// Quick TCP connection test first
		address := fmt.Sprintf("%s:%d", device.IP, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// Test RTSP authentication with ONVIF credentials
		streamPaths := []string{
			"/", "/live", "/stream", "/stream1", "/stream2",
			"/ch01", "/ch1", "/channel1", "/main", "/sub",
			"/cam/realmonitor?channel=1&subtype=0", // Dahua format
			"/Streaming/Channels/101",              // Hikvision format
		}

		if workingStreams := testRTSPCredentials(device.IP, port, username, password, streamPaths); len(workingStreams) > 0 {
			device.RTSPWorkingCreds = device.WorkingCreds
			device.RTSPStreams = workingStreams

			if isWeakCredential(username, password) {
				device.RTSPAuthStatus = "weak_auth"
				device.RTSPWeakPassword = true
				conditionalPrintf("[SUCCESS] RTSP authentication succeeded with ONVIF credentials: %s for %s:%d\n", device.WorkingCreds, device.IP, port)
				conditionalPrintf("[SUCCESS] Accessible RTSP streams: %v\n", workingStreams)
			} else {
				device.RTSPAuthStatus = "no_auth"
				conditionalPrintf("[SUCCESS] RTSP no authentication required (verified with ONVIF creds) for %s:%d\n", device.IP, port)
			}

			// Mark RTSP capability and service
			if device.Capabilities == nil {
				device.Capabilities = make(map[string]bool)
			}
			if device.Services == nil {
				device.Services = make(map[string]string)
			}
			device.Capabilities["RTSP"] = true
			device.Services["RTSP"] = fmt.Sprintf("rtsp://%s:%d", device.IP, port)

			return // Found working RTSP, no need to test other ports
		}
	}

	// If we reach here, ONVIF credentials didn't work for RTSP
	conditionalPrintf("[INFO] ONVIF credentials did not work for RTSP authentication on %s\n", device.IP)
}

// testRTSPOnDiscoveredDevice tests RTSP capabilities on an already discovered ONVIF device
func testRTSPOnDiscoveredDevice(device *Device) {
	// Initialize RTSP security fields
	device.RTSPAuthStatus = "unknown"
	device.RTSPWeakPassword = false
	device.RTSPStreams = []string{}

	// Test common RTSP ports on this device
	rtspPorts := []int{554, 8554, 1935, 8935}

	for _, port := range rtspPorts {
		// Quick TCP connection test
		address := fmt.Sprintf("%s:%d", device.IP, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// Found RTSP port, test authentication
		//fmt.Printf("[INFO] Found RTSP service on %s:%d, testing authentication...\n", device.IP, port)
		testRTSPAuthentication(device, device.IP, port)

		// Mark RTSP capability
		if device.Capabilities == nil {
			device.Capabilities = make(map[string]bool)
		}
		if device.Services == nil {
			device.Services = make(map[string]string)
		}
		device.Capabilities["RTSP"] = true
		device.Services["RTSP"] = fmt.Sprintf("rtsp://%s:%d", device.IP, port)

		// Found RTSP, no need to test other ports
		break
	}
}

// discoverRTSPDevices performs RTSP-based device discovery
func discoverRTSPDevices(cidr string, timeout time.Duration) ([]Device, error) {
	conditionalPrintf("[INFO] Starting RTSP device discovery on %s\n", cidr)

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []Device{}, err
	}

	var devices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Get all IPs in the CIDR range
	ips := getIPsFromCIDR(ipNet)

	// Create a channel to limit concurrent scans
	maxConcurrent := 50
	sem := make(chan struct{}, maxConcurrent)

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			device, found := scanRTSPDevice(ipAddr, timeout)
			if found {
				mu.Lock()
				devices = append(devices, device)
				mu.Unlock()
			}
		}(ip.String())
	}

	wg.Wait()
	return devices, nil
}

// scanRTSPDevice scans a single IP for RTSP services
func scanRTSPDevice(ip string, timeout time.Duration) (Device, bool) {
	for _, port := range rtspPorts {
		address := fmt.Sprintf("%s:%d", ip, port)

		// Test TCP connection to RTSP port
		conn, err := net.DialTimeout("tcp", address, timeout/10)
		if err != nil {
			continue
		}
		conn.Close()

		// Try RTSP handshake
		if device, found := detectRTSPDevice(ip, port, timeout/5); found {
			conditionalPrintf("[SUCCESS] Found RTSP device: %s at %s:%d\n", device.Name, ip, port)
			return device, true
		}
	}

	return Device{}, false
}

// detectRTSPDevice attempts RTSP handshake to identify device
func detectRTSPDevice(ip string, port int, timeout time.Duration) (Device, bool) {
	address := fmt.Sprintf("%s:%d", ip, port)

	// Try RTSP OPTIONS request
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return Device{}, false
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send RTSP OPTIONS request
	rtspRequest := fmt.Sprintf("OPTIONS rtsp://%s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ONVIF-Scanner/1.0\r\n\r\n", address)

	_, err = conn.Write([]byte(rtspRequest))
	if err != nil {
		return Device{}, false
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return Device{}, false
	}

	response := string(buffer[:n])

	// Check if it's a valid RTSP response
	if !strings.HasPrefix(response, "RTSP/1.0") {
		return Device{}, false
	}

	// Create device entry
	device := Device{
		Name:         fmt.Sprintf("RTSP Device (%s:%d)", ip, port),
		IP:           ip,
		Port:         port,
		XAddr:        fmt.Sprintf("rtsp://%s:%d", ip, port),
		AuthStatus:   "unknown",
		Capabilities: make(map[string]bool),
		Services:     make(map[string]string),
	}

	// Extract server information from response
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			serverInfo := strings.TrimSpace(line[7:])
			device.Manufacturer = extractManufacturerFromServer(serverInfo)
			device.Model = serverInfo
			break
		}
	}

	// Set RTSP capability
	device.Capabilities["RTSP"] = true
	device.Services["RTSP"] = device.XAddr

	// Initialize RTSP security fields
	device.RTSPAuthStatus = "unknown"
	device.RTSPWeakPassword = false
	device.RTSPStreams = []string{}

	// Test RTSP authentication
	testRTSPAuthentication(&device, ip, port)

	// Try to detect if this is likely an ONVIF device too
	if isLikelyONVIFDevice(response) {
		device.Capabilities["ONVIF"] = true
		// Try to find ONVIF endpoint
		onvifAddr := fmt.Sprintf("http://%s/onvif/device_service", ip)
		if testHTTPEndpoint(onvifAddr, timeout) {
			device.Services["ONVIF"] = onvifAddr
		}
	}

	return device, true
}

// extractManufacturerFromServer extracts manufacturer from RTSP server header
func extractManufacturerFromServer(serverInfo string) string {
	serverLower := strings.ToLower(serverInfo)

	manufacturers := map[string]string{
		"hikvision": "Hikvision",
		"dahua":     "Dahua",
		"uniview":   "Uniview",
		"axis":      "Axis",
		"bosch":     "Bosch",
		"panasonic": "Panasonic",
		"sony":      "Sony",
		"samsung":   "Samsung",
		"pelco":     "Pelco",
		"vivotek":   "Vivotek",
	}

	for keyword, manufacturer := range manufacturers {
		if strings.Contains(serverLower, keyword) {
			return manufacturer
		}
	}

	return "Unknown"
}

// isLikelyONVIFDevice checks if RTSP device likely supports ONVIF
func isLikelyONVIFDevice(rtspResponse string) bool {
	// Look for ONVIF-related headers or content
	responseLower := strings.ToLower(rtspResponse)
	onvifIndicators := []string{
		"onvif",
		"ptz",
		"profile",
		"wsse",
	}

	for _, indicator := range onvifIndicators {
		if strings.Contains(responseLower, indicator) {
			return true
		}
	}

	return false
}

// testHTTPEndpoint tests if an HTTP endpoint is accessible
func testHTTPEndpoint(url string, timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500
}

// discoverHTTPDevices performs HTTP fingerprinting for device discovery
func discoverHTTPDevices(cidr string, timeout time.Duration) ([]Device, error) {
	conditionalPrintf("[INFO] Starting HTTP fingerprinting discovery on %s\n", cidr)

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []Device{}, err
	}

	var devices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Get all IPs in the CIDR range
	ips := getIPsFromCIDR(ipNet)

	// Create a channel to limit concurrent scans
	maxConcurrent := 30
	sem := make(chan struct{}, maxConcurrent)

	// Common HTTP ports to check
	httpPorts := []int{80, 8080, 443, 8443, 8000, 8008, 9000, 9080}

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			device, found := scanHTTPFingerprint(ipAddr, httpPorts, timeout)
			if found {
				mu.Lock()
				devices = append(devices, device)
				mu.Unlock()
			}
		}(ip.String())
	}

	wg.Wait()
	return devices, nil
}

// scanHTTPFingerprint scans HTTP services for device fingerprinting
func scanHTTPFingerprint(ip string, ports []int, timeout time.Duration) (Device, bool) {
	for _, port := range ports {
		// Try both HTTP and HTTPS
		schemes := []string{"http", "https"}

		for _, scheme := range schemes {
			if device, found := fingerprintHTTPDevice(ip, port, scheme, timeout/10); found {
				conditionalPrintf("[SUCCESS] Found HTTP device: %s at %s://%s:%d\n", device.Name, scheme, ip, port)
				return device, true
			}
		}
	}

	return Device{}, false
}

// fingerprintHTTPDevice attempts to fingerprint device via HTTP
func fingerprintHTTPDevice(ip string, port int, scheme string, timeout time.Duration) (Device, bool) {
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, ip, port)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Try common camera web interface paths
	cameraPaths := []string{
		"/",
		"/index.html",
		"/home.html",
		"/login.html",
		"/webui/",
		"/web/",
		"/cgi-bin/",
		"/dvr/",
		"/cam/",
	}

	for _, path := range cameraPaths {
		url := baseURL + path

		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		// Read response body for fingerprinting
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			continue
		}

		// Analyze response for camera/NVR fingerprints
		if device, found := analyzeHTTPResponse(ip, port, scheme, resp, string(body)); found {
			return device, true
		}
	}

	return Device{}, false
}

// analyzeHTTPResponse analyzes HTTP response for camera/NVR fingerprints
func analyzeHTTPResponse(ip string, port int, scheme string, resp *http.Response, body string) (Device, bool) {
	// Check response headers and body for camera/NVR signatures
	headers := resp.Header
	bodyLower := strings.ToLower(body)

	device := Device{
		IP:           ip,
		Port:         port,
		XAddr:        fmt.Sprintf("%s://%s:%d", scheme, ip, port),
		AuthStatus:   "unknown",
		Capabilities: make(map[string]bool),
		Services:     make(map[string]string),
	}

	// Analyze Server header
	if server := headers.Get("Server"); server != "" {
		device.Manufacturer = extractManufacturerFromServer(server)
		device.Model = server
	}

	// Analyze WWW-Authenticate header for digest auth
	if auth := headers.Get("WWW-Authenticate"); auth != "" {
		if strings.Contains(strings.ToLower(auth), "digest") {
			device.Capabilities["DigestAuth"] = true
		}
	}

	// Check for camera/NVR specific signatures in body content
	signatures := map[string]string{
		"hikvision":              "Hikvision",
		"dahua":                  "Dahua",
		"uniview":                "Uniview",
		"axis":                   "Axis",
		"bosch":                  "Bosch",
		"panasonic":              "Panasonic",
		"sony":                   "Sony",
		"samsung":                "Samsung",
		"pelco":                  "Pelco",
		"vivotek":                "Vivotek",
		"foscam":                 "Foscam",
		"dlink":                  "D-Link",
		"tplink":                 "TP-Link",
		"netcam":                 "Generic NetCam",
		"ipcam":                  "Generic IPCam",
		"webcam":                 "Generic WebCam",
		"video surveillance":     "Video Surveillance",
		"network video recorder": "Network Video Recorder",
		"digital video recorder": "Digital Video Recorder",
		"web management":         "Web Management",
		"camera management":      "Camera Management",
		"live view":              "Live View Camera",
		"real-time":              "Real-time Camera",
	}

	foundSignature := false
	for signature, manufacturer := range signatures {
		if strings.Contains(bodyLower, signature) {
			if device.Manufacturer == "" || device.Manufacturer == "Unknown" {
				device.Manufacturer = manufacturer
			}
			foundSignature = true
			break
		}
	}

	// Check for specific camera web interface indicators
	cameraIndicators := []string{
		"live view", "camera", "video", "stream", "surveillance",
		"ptz", "preset", "record", "playback", "alarm", "motion detection",
		"dvr", "nvr", "ipcam", "webcam", "netcam",
	}

	indicatorCount := 0
	for _, indicator := range cameraIndicators {
		if strings.Contains(bodyLower, indicator) {
			indicatorCount++
		}
	}

	// If we found enough indicators, consider it a camera/NVR device
	if foundSignature || indicatorCount >= 2 {
		if device.Name == "" {
			if device.Manufacturer != "" && device.Manufacturer != "Unknown" {
				device.Name = fmt.Sprintf("%s Camera (%s:%d)", device.Manufacturer, ip, port)
			} else {
				device.Name = fmt.Sprintf("IP Camera (%s:%d)", ip, port)
			}
		}

		// Set capabilities based on content analysis
		device.Capabilities["HTTP"] = true
		device.Services["HTTP"] = device.XAddr

		if strings.Contains(bodyLower, "onvif") {
			device.Capabilities["ONVIF"] = true
		}
		if strings.Contains(bodyLower, "rtsp") {
			device.Capabilities["RTSP"] = true
		}
		if strings.Contains(bodyLower, "ptz") {
			device.Capabilities["PTZ"] = true
		}
		if strings.Contains(bodyLower, "recording") || strings.Contains(bodyLower, "playback") {
			device.Capabilities["Recording"] = true
		}

		return device, true
	}

	return Device{}, false
}

// discoverUPnPDevices performs UPnP device discovery via SSDP
func discoverUPnPDevices(timeout time.Duration) ([]Device, error) {
	conditionalPrintf("[INFO] Starting UPnP/SSDP device discovery...\n")

	var devices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	// UPnP multicast address and port
	ssdpAddr := "239.255.255.250:1900"

	// Create UDP connection
	conn, err := net.Dial("udp", ssdpAddr)
	if err != nil {
		return devices, err
	}
	defer conn.Close()

	// M-SEARCH request for media devices
	searchTargets := []string{
		"upnp:rootdevice",
		"urn:schemas-upnp-org:device:MediaServer:1",
		"urn:schemas-upnp-org:device:MediaRenderer:1",
		"urn:schemas-upnp-org:service:AVTransport:1",
		"urn:onvif-org:service:onvif:1",
	}

	for _, target := range searchTargets {
		wg.Add(1)
		go func(searchTarget string) {
			defer wg.Done()
			deviceList := performSSDPSearch(searchTarget, timeout)

			mu.Lock()
			devices = append(devices, deviceList...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	// Remove duplicates
	return removeDuplicateDevices(devices), nil
}

// performSSDPSearch performs SSDP M-SEARCH for specific device types
func performSSDPSearch(searchTarget string, timeout time.Duration) []Device {
	var devices []Device

	// Create UDP connection for SSDP
	addr, err := net.ResolveUDPAddr("udp", "239.255.255.250:1900")
	if err != nil {
		return devices
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return devices
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Prepare M-SEARCH request
	msearch := fmt.Sprintf(
		"M-SEARCH * HTTP/1.1\r\n"+
			"HOST: 239.255.255.250:1900\r\n"+
			"MAN: \"ssdp:discover\"\r\n"+
			"ST: %s\r\n"+
			"MX: %d\r\n\r\n",
		searchTarget, int(timeout.Seconds()))

	// Send M-SEARCH request
	_, err = conn.Write([]byte(msearch))
	if err != nil {
		return devices
	}

	// Collect responses
	responses := make(map[string]string) // Deduplicate by location
	buffer := make([]byte, 1024)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			break // Timeout or error
		}

		response := string(buffer[:n])

		// Parse SSDP response
		if device, found := parseSSDPResponse(response); found {
			// Use location as key to avoid duplicates
			location := device.Services["UPnP"]
			if location != "" {
				responses[location] = response
			}
		}
	}

	// Process unique responses
	for _, response := range responses {
		if device, found := parseSSDPResponse(response); found {
			devices = append(devices, device)
		}
	}

	return devices
}

// parseSSDPResponse parses SSDP response and extracts device information
func parseSSDPResponse(response string) (Device, bool) {
	if !strings.Contains(response, "HTTP/1.1 200 OK") {
		return Device{}, false
	}

	lines := strings.Split(response, "\r\n")
	headers := make(map[string]string)

	for _, line := range lines {
		if colonIndex := strings.Index(line, ":"); colonIndex > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:colonIndex]))
			value := strings.TrimSpace(line[colonIndex+1:])
			headers[key] = value
		}
	}

	// Extract key information
	location := headers["location"]
	server := headers["server"]
	st := headers["st"]
	usn := headers["usn"]

	if location == "" {
		return Device{}, false
	}

	// Parse IP from location URL
	ip := extractIPFromURL(location)
	if ip == "" {
		return Device{}, false
	}

	device := Device{
		IP:           ip,
		XAddr:        location,
		AuthStatus:   "unknown",
		Capabilities: make(map[string]bool),
		Services:     make(map[string]string),
		Scopes:       []string{},
	}

	// Set UPnP service
	device.Services["UPnP"] = location
	device.Capabilities["UPnP"] = true

	// Extract manufacturer from server header
	if server != "" {
		device.Manufacturer = extractManufacturerFromServer(server)
		device.Model = server
	}

	// Check if this might be a camera/media device
	if isCameraRelatedUPnP(st, usn, server) {
		device.Capabilities["Media"] = true

		if device.Manufacturer != "" {
			device.Name = fmt.Sprintf("%s UPnP Device (%s)", device.Manufacturer, ip)
		} else {
			device.Name = fmt.Sprintf("UPnP Media Device (%s)", ip)
		}

		// Try to fetch device description for more details
		if description := fetchUPnPDescription(location); description != "" {
			enhanceDeviceFromUPnPDescription(&device, description)
		}

		return device, true
	}

	return Device{}, false
}

// extractIPFromURL extracts IP address from URL
func extractIPFromURL(url string) string {
	// Remove protocol
	if idx := strings.Index(url, "://"); idx >= 0 {
		url = url[idx+3:]
	}

	// Extract host part
	if idx := strings.Index(url, "/"); idx >= 0 {
		url = url[:idx]
	}

	// Remove port if present
	if idx := strings.Index(url, ":"); idx >= 0 {
		url = url[:idx]
	}

	// Validate IP address
	if net.ParseIP(url) != nil {
		return url
	}

	return ""
}

// isCameraRelatedUPnP checks if UPnP device is camera/media related
func isCameraRelatedUPnP(st, usn, server string) bool {
	content := strings.ToLower(st + " " + usn + " " + server)

	indicators := []string{
		"media", "camera", "video", "onvif", "axis", "hikvision",
		"dahua", "uniview", "surveillance", "webcam", "ipcam",
		"avt", "imaging", "streaming",
	}

	for _, indicator := range indicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

// fetchUPnPDescription fetches and parses UPnP device description
func fetchUPnPDescription(location string) string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(location)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

// enhanceDeviceFromUPnPDescription extracts additional info from UPnP description XML
func enhanceDeviceFromUPnPDescription(device *Device, description string) {
	descLower := strings.ToLower(description)

	// Look for manufacturer in XML
	if strings.Contains(descLower, "<manufacturer>") {
		start := strings.Index(descLower, "<manufacturer>") + len("<manufacturer>")
		end := strings.Index(descLower[start:], "</manufacturer>")
		if end > 0 {
			manufacturer := strings.TrimSpace(description[start : start+end])
			if manufacturer != "" && device.Manufacturer == "" {
				device.Manufacturer = manufacturer
			}
		}
	}

	// Look for model name in XML
	if strings.Contains(descLower, "<modelname>") {
		start := strings.Index(descLower, "<modelname>") + len("<modelname>")
		end := strings.Index(descLower[start:], "</modelname>")
		if end > 0 {
			model := strings.TrimSpace(description[start : start+end])
			if model != "" {
				device.Model = model
				if device.Name == "" {
					device.Name = fmt.Sprintf("%s %s (%s)", device.Manufacturer, model, device.IP)
				}
			}
		}
	}

	// Look for serial number
	if strings.Contains(descLower, "<serialnumber>") {
		start := strings.Index(descLower, "<serialnumber>") + len("<serialnumber>")
		end := strings.Index(descLower[start:], "</serialnumber>")
		if end > 0 {
			serial := strings.TrimSpace(description[start : start+end])
			if serial != "" {
				device.SerialNumber = serial
			}
		}
	}
}

// testRTSPAuthentication tests RTSP authentication with weak credentials
func testRTSPAuthentication(device *Device, ip string, port int) {
	//fmt.Printf("[RTSP-SECURITY] Testing RTSP authentication for %s:%d...\n", ip, port)

	// Get all credentials (built-in + custom)
	allCredentials := getAllCredentials()
	//fmt.Printf("[RTSP-SECURITY] Testing %d credential combinations for RTSP...\n", len(allCredentials))

	// Common RTSP stream paths to test
	streamPaths := []string{
		"/",
		"/live",
		"/stream",
		"/stream1",
		"/stream2",
		"/live1",
		"/live2",
		"/ch01",
		"/ch1",
		"/channel1",
		"/main",
		"/sub",
		"/h264",
		"/mpeg4",
		"/mjpeg",
		"/cam/realmonitor?channel=1&subtype=0",  // Dahua format
		"/Streaming/Channels/101",               // Hikvision format
		"/ISAPI/Streaming/channels/101/picture", // Hikvision snapshot
		"/media/video1",                         // Generic
		"/av0_0",                                // Some Chinese cameras
		"/user=admin&password=&channel=1&stream=0.sdp", // URL params format
	}

	// Test each credential pair
	for _, creds := range allCredentials {
		username := creds[0]
		password := creds[1]

		credStr := fmt.Sprintf("%s:%s", username, password)

		//fmt.Printf("[RTSP-SECURITY] Trying RTSP credentials: %s\n", credStr)

		// Test authentication with different stream paths
		if workingStreams := testRTSPCredentials(ip, port, username, password, streamPaths); len(workingStreams) > 0 {
			device.RTSPWorkingCreds = credStr
			device.RTSPStreams = workingStreams

			if isWeakCredential(username, password) {
				device.RTSPAuthStatus = "weak_auth"
				device.RTSPWeakPassword = true
				conditionalPrintf("[RTSP-WARNING] Weak RTSP credentials found: %s for %s:%d\n", credStr, ip, port)
				conditionalPrintf("[RTSP-WARNING] Accessible streams: %v\n", workingStreams)
			} else {
				device.RTSPAuthStatus = "no_auth"
				conditionalPrintf("[RTSP-INFO] No RTSP authentication required for %s:%d\n", ip, port)
				conditionalPrintf("[RTSP-INFO] Accessible streams: %v\n", workingStreams)
			}
			return
		}
	}

	device.RTSPAuthStatus = "auth_required"
	conditionalPrintf("[RTSP-INFO] All weak credentials failed for RTSP %s:%d\n", ip, port)
}

// testRTSPCredentials tests RTSP credentials against multiple stream paths
func testRTSPCredentials(ip string, port int, username, password string, streamPaths []string) []string {
	var workingStreams []string

	// Test each stream path
	for _, path := range streamPaths {
		streamURL := fmt.Sprintf("rtsp://%s:%d%s", ip, port, path)

		if testRTSPStream(streamURL, username, password) {
			workingStreams = append(workingStreams, streamURL)
			// Don't test all paths if we found working streams (performance optimization)
			if len(workingStreams) >= 3 {
				break
			}
		}
	}

	return workingStreams
}

// testRTSPStream tests access to a specific RTSP stream
func testRTSPStream(streamURL, username, password string) bool {
	// Parse URL to get host and port
	if !strings.HasPrefix(streamURL, "rtsp://") {
		return false
	}

	// Extract host:port from URL
	urlPart := streamURL[7:] // Remove "rtsp://"
	var hostPort string
	if slashIndex := strings.Index(urlPart, "/"); slashIndex > 0 {
		hostPort = urlPart[:slashIndex]
	} else {
		hostPort = urlPart
	}

	// Connect to RTSP server
	conn, err := net.DialTimeout("tcp", hostPort, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Send RTSP DESCRIBE request
	var request string
	if username != "" || password != "" {
		// Create basic auth header
		auth := fmt.Sprintf("%s:%s", username, password)
		authEncoded := fmt.Sprintf("Basic %s", encodeBase64(auth))
		request = fmt.Sprintf(
			"DESCRIBE %s RTSP/1.0\r\n"+
				"CSeq: 1\r\n"+
				"User-Agent: ONVIF-Scanner/1.0\r\n"+
				"Authorization: %s\r\n"+
				"Accept: application/sdp\r\n\r\n",
			streamURL, authEncoded)
	} else {
		request = fmt.Sprintf(
			"DESCRIBE %s RTSP/1.0\r\n"+
				"CSeq: 1\r\n"+
				"User-Agent: ONVIF-Scanner/1.0\r\n"+
				"Accept: application/sdp\r\n\r\n",
			streamURL)
	}

	// Send request
	_, err = conn.Write([]byte(request))
	if err != nil {
		return false
	}

	// Read response
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return false
	}

	response := string(buffer[:n])

	// Check response status
	if strings.Contains(response, "RTSP/1.0 200 OK") {
		// Success - stream is accessible
		return true
	} else if strings.Contains(response, "RTSP/1.0 401") {
		// Authentication required but credentials failed
		return false
	} else if strings.Contains(response, "RTSP/1.0 404") {
		// Stream path not found
		return false
	}

	return false
}

// encodeBase64 encodes string to base64 (simple implementation)
func encodeBase64(s string) string {
	// Simple base64 encoding for basic auth
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	input := []byte(s)
	result := ""

	for i := 0; i < len(input); i += 3 {
		// Process 3 bytes at a time
		var b1, b2, b3 byte
		if i < len(input) {
			b1 = input[i]
		}
		if i+1 < len(input) {
			b2 = input[i+1]
		}
		if i+2 < len(input) {
			b3 = input[i+2]
		}

		// Convert to 4 base64 characters
		result += string(base64Chars[(b1>>2)&0x3F])
		result += string(base64Chars[((b1<<4)|(b2>>4))&0x3F])

		if i+1 < len(input) {
			result += string(base64Chars[((b2<<2)|(b3>>6))&0x3F])
		} else {
			result += "="
		}

		if i+2 < len(input) {
			result += string(base64Chars[b3&0x3F])
		} else {
			result += "="
		}
	}

	return result
}
