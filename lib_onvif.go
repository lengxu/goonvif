package onvif

import (
	"encoding/json"
	"github.com/golang/glog"
	"net"
	"strings"
	"time"
)

var (
	mapProfile    = make(map[string]string) // key: device XAddr, value: profile of device
	mapPtzXAddr   = make(map[string]string)
	mapMediaXAddr = make(map[string]string)
)

type OnvifData struct {
	Error string
	Data  interface{}
}

func DiscoveryDeviceByIp(ip string, duration int) string {
	result := OnvifData{}
	result.Error = ""
	
	// Handle auto discovery - now uses hybrid approach
	if ip == "auto" || ip == "all" {
		devices, err := StartDiscoveryAuto(time.Duration(duration)*time.Millisecond)
		if err != nil {
			result.Error = err.Error()
		}
		result.Data = devices
	} else if strings.Contains(ip, ",") {
		// Handle multiple CIDR ranges (comma-separated) - now uses hybrid approach
		cidrs := strings.Split(ip, ",")
		for i, cidr := range cidrs {
			cidrs[i] = strings.TrimSpace(cidr)
		}
		devices, err := StartDiscoveryOnMultipleCIDRs(cidrs, time.Duration(duration)*time.Millisecond)
		if err != nil {
			result.Error = err.Error()
		}
		result.Data = devices
	} else if strings.Contains(ip, "/") {
		// Handle single CIDR range - now automatically chooses best method
		devices, err := StartDiscoveryOnCIDR(ip, time.Duration(duration)*time.Millisecond)
		if err != nil {
			result.Error = err.Error()
		}
		result.Data = devices
	} else {
		// Handle single IP discovery - for cross-network IPs, use TCP scanning only
		var allDevices []Device
		
		// First try TCP scanning (works for cross-network)
		tcpDevice, found := scanOnvifDevice(ip, time.Duration(duration)*time.Millisecond)
		if found {
			allDevices = append(allDevices, tcpDevice)
		}
		
		// Skip WS-Discovery for cross-network discovery to avoid binding issues
		// WS-Discovery only works within the same broadcast domain
		
		result.Data = allDevices
	}
	
	str, _ := json.Marshal(result)
	return string(str)
}

func DiscoveryDevice(interfaceName string, duration int) string {
	result := OnvifData{}
	itf, err := net.InterfaceByName(interfaceName) //here your interface

	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	item, _ := itf.Addrs()
	var ip net.IP
	for _, addr := range item {
		switch v := addr.(type) {
		case *net.IPNet:
			if !v.IP.IsLoopback() {
				if v.IP.To4() != nil { //Verify if IP is IPV4
					ip = v.IP
					break
				}
			}
		}
	}

	if ip == nil {
		result.Error = "Could not find a IP on " + interfaceName
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Discover device on interface's network
	result.Error = ""
	devices, err := discoverDevices(ip.String(), time.Duration(duration)*time.Millisecond)
	if err != nil {
		result.Error = err.Error()
	}
	result.Data = devices
	str, _ := json.Marshal(result)
	return string(str)
}

func GetInformation(host, username, password string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Call GetInformation
	getInfo, err := device.GetInformation()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = getInfo
	str, _ := json.Marshal(result)
	return string(str)
}

func GetProfiles(host, username, password string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Call GetProfiles
	profiles, err := device.GetMediaProfiles()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = profiles
	str, _ := json.Marshal(result)
	return string(str)
}

func GetProfilesWithCallback(host, username, password string, ProfileFunc func(interface{})) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Call GetProfiles
	profiles, err := device.GetMediaProfiles()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	ProfileFunc(profiles)

	result.Error = ""
	result.Data = profiles
	str, _ := json.Marshal(result)
	return string(str)
}

func GetDeviceInformation(host, username, password string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Call GetDeviceInformation
	deviceInfo, err := device.GetDeviceInformation()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = deviceInfo
	str, _ := json.Marshal(result)
	return string(str)
}

func GetCapabilities(host, username, password string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Call GetCapabilities
	capabilities, err := device.GetCapabilities()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = capabilities
	str, _ := json.Marshal(result)
	return string(str)
}

func GetStreamUri(host, username, password, profile string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Store profile token to map
	mapProfile[host] = profile

	// Get MediaXAddr for getting streaming uri
	capabilities, err := device.GetCapabilities()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Parse capabilities response
	if err == nil {
		glog.Info("GetCapabilities response:", capabilities)

		// Try to extract media XAddr from DeviceCapabilities struct
		if capabilities.Media.XAddr != "" {
			mapMediaXAddr[host] = capabilities.Media.XAddr
		}
	}

	// Call GetStreamUri
	var mediaXAddr string
	if mapMediaXAddr[host] != "" {
		mediaXAddr = mapMediaXAddr[host]
	} else {
		mediaXAddr = host
	}

	//  Use device method if implemented, otherwise fallback
	mediaDevice := Device{
		XAddr:    mediaXAddr,
		User:     username,
		Password: password,
	}

	mediaDevice.Login()
	if mediaDevice.ErrorMsg != "" {
		result.Error = mediaDevice.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	streamURI, err := mediaDevice.GetStreamURI(profile, "RTP-Unicast")
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = streamURI
	str, _ := json.Marshal(result)
	return string(str)
}

func PtzContinuousMove(host, username, password, x, y, z string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	var profile string
	if mapProfile[host] != "" {
		profile = mapProfile[host]
	} else {
		// Get a default profile if not stored
		profiles, err := device.GetMediaProfiles()
		if err != nil {
			result.Error = "Failed to get profiles: " + err.Error()
			str, _ := json.Marshal(result)
			return string(str)
		}

		if profileList, ok := profiles.([]interface{}); ok && len(profileList) > 0 {
			if firstProfile, ok := profileList[0].(map[string]interface{}); ok {
				if token, ok := firstProfile["Token"].(string); ok {
					profile = token
					mapProfile[host] = profile
				}
			}
		}
	}

	if profile == "" {
		result.Error = "No profile token available"
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Get PTZ capabilities and XAddr
	capabilities, err := device.GetCapabilities()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Parse capabilities response to get PTZ XAddr
	if err == nil {
		if capabilities.Ptz.XAddr != "" {
			mapPtzXAddr[host] = capabilities.Ptz.XAddr
		}
	}

	var ptzXAddr string
	if mapPtzXAddr[host] != "" {
		ptzXAddr = mapPtzXAddr[host]
	} else {
		ptzXAddr = host
	}

	ptzDevice := Device{
		XAddr:    ptzXAddr,
		User:     username,
		Password: password,
	}

	ptzDevice.Login()
	if ptzDevice.ErrorMsg != "" {
		result.Error = ptzDevice.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	status, err := ptzDevice.PTZContinuousMove(profile, x, y, z)
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = status
	str, _ := json.Marshal(result)
	return string(str)
}

func PtzRelativeMove(host, username, password, x, y, z string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	var profile string
	if mapProfile[host] != "" {
		profile = mapProfile[host]
	} else {
		// Get a default profile if not stored
		profiles, err := device.GetMediaProfiles()
		if err != nil {
			result.Error = "Failed to get profiles: " + err.Error()
			str, _ := json.Marshal(result)
			return string(str)
		}

		if profileList, ok := profiles.([]interface{}); ok && len(profileList) > 0 {
			if firstProfile, ok := profileList[0].(map[string]interface{}); ok {
				if token, ok := firstProfile["Token"].(string); ok {
					profile = token
					mapProfile[host] = profile
				}
			}
		}
	}

	if profile == "" {
		result.Error = "No profile token available"
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Get PTZ capabilities and XAddr
	capabilities, err := device.GetCapabilities()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Parse capabilities response to get PTZ XAddr
	if err == nil {
		if capabilities.Ptz.XAddr != "" {
			mapPtzXAddr[host] = capabilities.Ptz.XAddr
		}
	}

	var ptzXAddr string
	if mapPtzXAddr[host] != "" {
		ptzXAddr = mapPtzXAddr[host]
	} else {
		ptzXAddr = host
	}

	ptzDevice := Device{
		XAddr:    ptzXAddr,
		User:     username,
		Password: password,
	}

	ptzDevice.Login()
	if ptzDevice.ErrorMsg != "" {
		result.Error = ptzDevice.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	status, err := ptzDevice.PTZRelativeMove(profile, x, y, z)
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = status
	str, _ := json.Marshal(result)
	return string(str)
}

func PtzStop(host, username, password string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	var profile string
	if mapProfile[host] != "" {
		profile = mapProfile[host]
	} else {
		// Get a default profile if not stored
		profiles, err := device.GetMediaProfiles()
		if err != nil {
			result.Error = "Failed to get profiles: " + err.Error()
			str, _ := json.Marshal(result)
			return string(str)
		}

		if profileList, ok := profiles.([]interface{}); ok && len(profileList) > 0 {
			if firstProfile, ok := profileList[0].(map[string]interface{}); ok {
				if token, ok := firstProfile["Token"].(string); ok {
					profile = token
					mapProfile[host] = profile
				}
			}
		}
	}

	if profile == "" {
		result.Error = "No profile token available"
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Get PTZ capabilities and XAddr
	capabilities, err := device.GetCapabilities()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Parse capabilities response to get PTZ XAddr
	if err == nil {
		if capabilities.Ptz.XAddr != "" {
			mapPtzXAddr[host] = capabilities.Ptz.XAddr
		}
	}

	var ptzXAddr string
	if mapPtzXAddr[host] != "" {
		ptzXAddr = mapPtzXAddr[host]
	} else {
		ptzXAddr = host
	}

	ptzDevice := Device{
		XAddr:    ptzXAddr,
		User:     username,
		Password: password,
	}

	ptzDevice.Login()
	if ptzDevice.ErrorMsg != "" {
		result.Error = ptzDevice.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	status, err := ptzDevice.PTZStop(profile)
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = status
	str, _ := json.Marshal(result)
	return string(str)
}

func PtzGoToHome(host, username, password string) string {
	result := OnvifData{}
	device := Device{
		XAddr:    host,
		User:     username,
		Password: password,
	}

	device.Login()
	if device.ErrorMsg != "" {
		result.Error = device.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	var profile string
	if mapProfile[host] != "" {
		profile = mapProfile[host]
	} else {
		// Get a default profile if not stored
		profiles, err := device.GetMediaProfiles()
		if err != nil {
			result.Error = "Failed to get profiles: " + err.Error()
			str, _ := json.Marshal(result)
			return string(str)
		}

		if profileList, ok := profiles.([]interface{}); ok && len(profileList) > 0 {
			if firstProfile, ok := profileList[0].(map[string]interface{}); ok {
				if token, ok := firstProfile["Token"].(string); ok {
					profile = token
					mapProfile[host] = profile
				}
			}
		}
	}

	if profile == "" {
		result.Error = "No profile token available"
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Get PTZ capabilities and XAddr
	capabilities, err := device.GetCapabilities()
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	// Parse capabilities response to get PTZ XAddr
	if err == nil {
		if capabilities.Ptz.XAddr != "" {
			mapPtzXAddr[host] = capabilities.Ptz.XAddr
		}
	}

	var ptzXAddr string
	if mapPtzXAddr[host] != "" {
		ptzXAddr = mapPtzXAddr[host]
	} else {
		ptzXAddr = host
	}

	ptzDevice := Device{
		XAddr:    ptzXAddr,
		User:     username,
		Password: password,
	}

	ptzDevice.Login()
	if ptzDevice.ErrorMsg != "" {
		result.Error = ptzDevice.ErrorMsg
		str, _ := json.Marshal(result)
		return string(str)
	}

	status, err := ptzDevice.PTZGotoHomePosition(profile)
	if err != nil {
		result.Error = err.Error()
		str, _ := json.Marshal(result)
		return string(str)
	}

	result.Error = ""
	result.Data = status
	str, _ := json.Marshal(result)
	return string(str)
}


// isLikelyLocalIP checks if an IP address is likely on the local network
func isLikelyLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// Get local network interfaces
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	
	// Check if IP is in any local network range
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			if ipNet.Contains(ip) {
				return true
			}
		}
	}
	
	return false
}