package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"bufio"

	onvif "github.com/quocson95/go-onvif"
)

func main() {
	var (
		command    = flag.String("cmd", "discover", "Command to execute: discover, info, media, ptz")
		ip         = flag.String("ip", "", "Target IP address or network interface name")
		host       = flag.String("host", "", "ONVIF device host URL (e.g., http://192.168.1.100/onvif/device_service)")
		username   = flag.String("user", "admin", "Username for authentication")
		password   = flag.String("pass", "admin", "Password for authentication")
		duration   = flag.Int("timeout", 3000, "Discovery timeout in milliseconds")
		output     = flag.String("output", "", "Output file path for JSON results (optional)")
		credsFile  = flag.String("creds", "", "Custom credentials file (username:password per line)")
		help       = flag.Bool("help", false, "Show help information")
	)

	flag.Parse()

	if *help {
		showHelp()
		return
	}

	switch *command {
	case "discover":
		if *ip == "" {
			fmt.Println("Error: IP address, CIDR subnet, or interface name required for discovery")
			os.Exit(1)
		}
		discoverDevices(*ip, *duration, *output, *credsFile)

	case "info":
		if *host == "" {
			fmt.Println("Error: Host URL required for device info")
			os.Exit(1)
		}
		getDeviceInfo(*host, *username, *password)

	case "media":
		if *host == "" {
			fmt.Println("Error: Host URL required for media info")
			os.Exit(1)
		}
		getMediaInfo(*host, *username, *password)

	case "ptz":
		if *host == "" {
			fmt.Println("Error: Host URL required for PTZ info")
			os.Exit(1)
		}
		getPTZInfo(*host, *username, *password)

	default:
		fmt.Printf("Error: Unknown command '%s'\n", *command)
		showHelp()
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Println("ONVIF Device Management Tool")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  onvif [options]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  discover  - Discover ONVIF devices on network")
	fmt.Println("  info      - Get device information")
	fmt.Println("  media     - Get media profiles and capabilities")
	fmt.Println("  ptz       - Get PTZ capabilities and status")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -cmd string      Command to execute (default: discover)")
	fmt.Println("  -ip string       IP address, CIDR subnet, or network interface for discovery")
	fmt.Println("  -host string     ONVIF device host URL")
	fmt.Println("  -user string     Username (default: admin)")
	fmt.Println("  -pass string     Password (default: admin)")
	fmt.Println("  -timeout int     Discovery timeout in ms (default: 3000)")
	fmt.Println("  -output string   Output file path for JSON results (optional)")
	fmt.Println("  -creds string    Custom credentials file path (username:password per line)")
	fmt.Println("  -help            Show this help")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  # Discover devices with multiple methods and security scan")
	fmt.Println("  onvif -cmd discover -ip 192.168.1.0/24")
	fmt.Println("")
	fmt.Println("  # Use custom credentials file for weak password testing")
	fmt.Println("  onvif -cmd discover -ip 192.168.1.0/24 -creds my_passwords.txt")
	fmt.Println("")
	fmt.Println("  # Auto-discover with all methods and save comprehensive results")
	fmt.Println("  onvif -cmd discover -ip auto -timeout 15000 -output full_scan.json")
	fmt.Println("")
	fmt.Println("  # Targeted network scan with security analysis")
	fmt.Println("  onvif -cmd discover -ip 10.0.0.0/16 -output security_audit.json")
	fmt.Println("")
	fmt.Println("Discovery Methods:")
	fmt.Println("  • ONVIF WS-Discovery (UDP multicast)")
	fmt.Println("  • ONVIF TCP port scanning (cross-network)")
	fmt.Println("  • RTSP device detection (554, 8554, etc.) + stream access testing")
	fmt.Println("  • HTTP fingerprinting (camera web interfaces)")
	fmt.Println("  • UPnP/SSDP discovery (media devices)")
	fmt.Println("  • Weak credential testing for ONVIF + RTSP (configurable)")
	fmt.Println("")
	fmt.Println("Security Testing Features:")
	fmt.Println("  • ONVIF authentication bypass detection")
	fmt.Println("  • RTSP stream access with weak credentials")
	fmt.Println("  • Automatic stream URL discovery (Hikvision/Dahua/Generic paths)")
	fmt.Println("  • Comprehensive vulnerability reporting")
	fmt.Println("  • Critical device identification (dual protocol vulnerabilities)")
	fmt.Println("")
	fmt.Println("Credentials File Format:")
	fmt.Println("  username:password")
	fmt.Println("  admin:")
	fmt.Println("  admin:123456")
	fmt.Println("  # Comments start with #")
	fmt.Println("")
	fmt.Println("  # Get device info")
	fmt.Println("  onvif -cmd info -host http://192.168.1.100/onvif/device_service -user admin -pass 123456")
	fmt.Println("")
	fmt.Println("  # Get media capabilities")
	fmt.Println("  onvif -cmd media -host http://192.168.1.100/onvif/device_service -user admin -pass 123456")
}

func discoverDevices(ip string, duration int, outputPath string, credsFile string) {
	var ipType string
	if strings.Contains(ip, "/") {
		ipType = "CIDR subnet"
	} else if strings.Contains(ip, ".") {
		ipType = "IP address"
	} else {
		ipType = "interface"
	}
	
	fmt.Printf("Discovering ONVIF devices on %s %s (timeout: %dms)...\n", ipType, ip, duration)
	fmt.Printf("Security scan enabled: Testing for weak credentials...\n")
	
	// Load custom credentials if file provided
	if credsFile != "" {
		if err := loadCustomCredentials(credsFile); err != nil {
			fmt.Printf("Warning: Failed to load credentials file %s: %v\n", credsFile, err)
		} else {
			fmt.Printf("Loaded custom credentials from: %s\n", credsFile)
		}
	}
	
	var result string
	// Check if ip looks like an interface name, IP address, or CIDR
	if strings.Contains(ip, ".") || strings.Contains(ip, "/") {
		result = onvif.DiscoveryDeviceByIp(ip, duration)
	} else {
		result = onvif.DiscoveryDevice(ip, duration)
	}

	var data onvif.OnvifData
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		fmt.Printf("Error parsing discovery result: %v\n", err)
		return
	}

	if data.Error != "" {
		fmt.Printf("Discovery error: %s\n", data.Error)
		return
	}

	devices, ok := data.Data.([]interface{})
	if !ok {
		fmt.Println("No devices found")
		return
	}

	fmt.Printf("Found %d device(s):\n", len(devices))
	
	// Print summary and security analysis
	weakDevices := 0
	noAuthDevices := 0
	rtspWeakDevices := 0
	rtspNoAuthDevices := 0
	
	for i, device := range devices {
		deviceJSON, _ := json.MarshalIndent(device, "", "  ")
		fmt.Printf("Device %d:\n%s\n\n", i+1, string(deviceJSON))
		
		// Count security issues
		if deviceMap, ok := device.(map[string]interface{}); ok {
			// ONVIF security
			if authStatus, exists := deviceMap["auth_status"]; exists {
				switch authStatus {
				case "weak_auth":
					weakDevices++
				case "no_auth":
					noAuthDevices++
				}
			}
			
			// RTSP security
			if rtspAuthStatus, exists := deviceMap["rtsp_auth_status"]; exists {
				switch rtspAuthStatus {
				case "weak_auth":
					rtspWeakDevices++
				case "no_auth":
					rtspNoAuthDevices++
				}
			}
		}
	}
	
	// Print comprehensive security summary
	fmt.Printf("\n=== COMPREHENSIVE SECURITY SUMMARY ===\n")
	fmt.Printf("Total devices found: %d\n", len(devices))
	fmt.Printf("\nONVIF Security:\n")
	fmt.Printf("  Devices with weak ONVIF credentials: %d\n", weakDevices)
	fmt.Printf("  Devices with no ONVIF authentication: %d\n", noAuthDevices)
	fmt.Printf("\nRTSP Security:\n")
	fmt.Printf("  Devices with weak RTSP credentials: %d\n", rtspWeakDevices)
	fmt.Printf("  Devices with no RTSP authentication: %d\n", rtspNoAuthDevices)
	
	totalVulnerable := weakDevices + noAuthDevices + rtspWeakDevices + rtspNoAuthDevices
	if totalVulnerable > 0 {
		fmt.Printf("\n⚠️  CRITICAL: %d protocol vulnerabilities found across devices!\n", totalVulnerable)
		fmt.Printf("   - ONVIF vulnerabilities: %d\n", weakDevices+noAuthDevices)
		fmt.Printf("   - RTSP vulnerabilities: %d\n", rtspWeakDevices+rtspNoAuthDevices)
	} else {
		fmt.Printf("\n✅ No obvious security vulnerabilities found\n")
	}
	
	// Save to JSON file if output path provided
	if outputPath != "" {
		saveToJSON(devices, outputPath)
	}
}

// saveToJSON saves the device list to a JSON file
func saveToJSON(devices []interface{}, filepath string) {
	// Create enhanced output structure
	output := map[string]interface{}{
		"scan_time":    fmt.Sprintf("%v", strings.Split(fmt.Sprintf("%v", os.Args), " ")),
		"total_devices": len(devices),
		"devices":      devices,
	}
	
	// Count security statistics
	weakCount := 0
	noAuthCount := 0
	authRequiredCount := 0
	
	// RTSP security statistics
	rtspWeakCount := 0
	rtspNoAuthCount := 0
	rtspAuthRequiredCount := 0
	
	for _, device := range devices {
		if deviceMap, ok := device.(map[string]interface{}); ok {
			// ONVIF security
			if authStatus, exists := deviceMap["auth_status"]; exists {
				switch authStatus {
				case "weak_auth":
					weakCount++
				case "no_auth":
					noAuthCount++
				case "auth_required":
					authRequiredCount++
				}
			}
			
			// RTSP security
			if rtspAuthStatus, exists := deviceMap["rtsp_auth_status"]; exists {
				switch rtspAuthStatus {
				case "weak_auth":
					rtspWeakCount++
				case "no_auth":
					rtspNoAuthCount++
				case "auth_required":
					rtspAuthRequiredCount++
				}
			}
		}
	}
	
	output["security_summary"] = map[string]interface{}{
		"onvif_security": map[string]interface{}{
			"devices_with_weak_auth":   weakCount,
			"devices_with_no_auth":     noAuthCount,
			"devices_requiring_auth":   authRequiredCount,
			"vulnerable_devices":       weakCount + noAuthCount,
		},
		"rtsp_security": map[string]interface{}{
			"devices_with_weak_auth":   rtspWeakCount,
			"devices_with_no_auth":     rtspNoAuthCount,
			"devices_requiring_auth":   rtspAuthRequiredCount,
			"vulnerable_devices":       rtspWeakCount + rtspNoAuthCount,
		},
		"total_vulnerabilities": weakCount + noAuthCount + rtspWeakCount + rtspNoAuthCount,
		"critical_devices":      countCriticalDevices(devices),
	}
	
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}
	
	err = os.WriteFile(filepath, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing to file %s: %v\n", filepath, err)
		return
	}
	
	fmt.Printf("\n📄 Results saved to: %s\n", filepath)
}

// countCriticalDevices counts devices with both ONVIF and RTSP vulnerabilities
func countCriticalDevices(devices []interface{}) int {
	critical := 0
	
	for _, device := range devices {
		if deviceMap, ok := device.(map[string]interface{}); ok {
			onvifVuln := false
			rtspVuln := false
			
			// Check ONVIF vulnerabilities
			if authStatus, exists := deviceMap["auth_status"]; exists {
				if authStatus == "weak_auth" || authStatus == "no_auth" {
					onvifVuln = true
				}
			}
			
			// Check RTSP vulnerabilities  
			if rtspAuthStatus, exists := deviceMap["rtsp_auth_status"]; exists {
				if rtspAuthStatus == "weak_auth" || rtspAuthStatus == "no_auth" {
					rtspVuln = true
				}
			}
			
			// Device is critical if it has vulnerabilities in both protocols
			if onvifVuln && rtspVuln {
				critical++
			}
		}
	}
	
	return critical
}

// loadCustomCredentials loads credentials from a file and adds them to the global list
func loadCustomCredentials(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	var customCreds [][]string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse username:password format
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			fmt.Printf("Warning: Invalid format at line %d: %s (expected username:password)\n", lineNum, line)
			continue
		}
		
		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])
		customCreds = append(customCreds, []string{username, password})
	}
	
	if err := scanner.Err(); err != nil {
		return err
	}
	
	// Update the global credentials in the onvif package
	onvif.SetCustomCredentials(customCreds)
	fmt.Printf("Loaded %d custom credential pairs\n", len(customCreds))
	
	return nil
}

// generateCredentialsTemplate creates a sample credentials file
func generateCredentialsTemplate() {
	templateContent := `# ONVIF Weak Credentials File
# Format: username:password (one per line)
# Lines starting with # are comments
# Empty passwords are allowed (use username: with nothing after colon)

# Default/Empty credentials
:
admin:
root:

# Common weak passwords
admin:admin
admin:123456
admin:12345
admin:password
admin:888888
admin:111111
admin:000000
admin:9999
admin:1234
admin:admin123

# Manufacturer defaults
hikvision:hikvision
dahua:dahua
uniview:uniview

# Service accounts
user:user
guest:guest
operator:operator
service:service
viewer:viewer

# Add your custom credentials below:
# customuser:custompass
`

	err := os.WriteFile("credentials.txt", []byte(templateContent), 0644)
	if err != nil {
		fmt.Printf("Error creating credentials template: %v\n", err)
		return
	}
	
	fmt.Println("📄 Created credentials template: credentials.txt")
	fmt.Println("Edit this file to add your custom weak credentials for testing.")
}

func getDeviceInfo(host, username, password string) {
	fmt.Printf("Getting device information from %s...\n", host)
	
	device := onvif.Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	info, err := device.GetInformation()
	if err != nil {
		fmt.Printf("Error getting device info: %v\n", err)
		return
	}

	infoJSON, _ := json.MarshalIndent(info, "", "  ")
	fmt.Printf("Device Information:\n%s\n", string(infoJSON))

	caps, err := device.GetCapabilities()
	if err != nil {
		fmt.Printf("Error getting capabilities: %v\n", err)
		return
	}

	capsJSON, _ := json.MarshalIndent(caps, "", "  ")
	fmt.Printf("\nDevice Capabilities:\n%s\n", string(capsJSON))
}

func getMediaInfo(host, username, password string) {
	fmt.Printf("Getting media information from %s...\n", host)
	
	result := onvif.GetProfiles(host, username, password)
	
	var data onvif.OnvifData
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		fmt.Printf("Error parsing media result: %v\n", err)
		return
	}

	if data.Error != "" {
		fmt.Printf("Media error: %s\n", data.Error)
		return
	}

	mediaJSON, _ := json.MarshalIndent(data.Data, "", "  ")
	fmt.Printf("Media Information:\n%s\n", string(mediaJSON))
}

func getPTZInfo(host, username, password string) {
	fmt.Printf("Getting PTZ information from %s...\n", host)
	
	device := onvif.Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	// Get capabilities first to get PTZ service URL
	caps, err := device.GetCapabilities()
	if err != nil {
		fmt.Printf("Error getting capabilities: %v\n", err)
		return
	}

	if caps.Ptz.XAddr == "" {
		fmt.Println("PTZ not supported by this device")
		return
	}

	fmt.Printf("PTZ Service URL: %s\n", caps.Ptz.XAddr)
	
	// Try to get PTZ configurations
	ptzDevice := onvif.Device{
		XAddr:    caps.Ptz.XAddr,
		User:     username,
		Password: password,
	}

	configs, err := ptzDevice.GetConfigurations()
	if err != nil {
		fmt.Printf("Error getting PTZ configurations: %v\n", err)
		return
	}

	configsJSON, _ := json.MarshalIndent(configs, "", "  ")
	fmt.Printf("PTZ Configurations:\n%s\n", string(configsJSON))
}