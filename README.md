# Go-ONVIF 摄像头安全扫描工具

Go-ONVIF 是一个专业的网络摄像头发现和安全审计工具，支持多种发现协议和全面的弱口令检测。该工具特别针对中国市场的主流摄像头品牌（海康威视、大华技术、宇视科技等）进行了深度优化。

## 🚀 核心功能特性

### 多协议设备发现
- **ONVIF WS-Discovery** - UDP组播发现（本地网络）
- **ONVIF TCP扫描** - 跨网段TCP端口扫描
- **RTSP设备检测** - 流媒体服务发现
- **HTTP指纹识别** - Web界面特征检测
- **UPnP/SSDP发现** - 媒体设备通用发现

### 双协议安全检测
- **ONVIF弱口令检测** - 管理接口认证测试
- **RTSP流访问测试** - 视频流弱口令检测
- **自动流URL发现** - 支持海康/大华/通用格式
- **可配置密码字典** - 支持自定义凭据文件
- **综合安全报告** - JSON格式详细输出

## 📥 安装使用

### 编译安装
```bash
# 克隆项目
git clone https://github.com/quocson95/go-onvif.git
cd go-onvif

# 编译CLI工具
go build ./cmd/onvif

# 或使用跨平台编译脚本
./build.sh
```

### 快速开始
```bash
# 基本网络扫描
./onvif -cmd discover -ip 192.168.1.0/24

# 使用自定义密码字典
./onvif -cmd discover -ip 192.168.1.0/24 -creds my_passwords.txt

# 全网段扫描并保存结果
./onvif -cmd discover -ip auto -timeout 15000 -output security_audit.json
```

## 🔧 详细使用说明

### 命令行参数
```
-cmd string      命令类型 (discover/info/media/ptz，默认: discover)
-ip string       目标IP、CIDR网段或网络接口名
-host string     ONVIF设备URL（用于info/media/ptz命令）
-user string     用户名（默认: admin）
-pass string     密码（默认: admin）
-timeout int     发现超时时间，毫秒（默认: 3000）
-output string   JSON结果输出文件路径（可选）
-creds string    自定义凭据文件路径（可选）
-help            显示帮助信息
```

### 发现模式示例

#### 1. 单一IP扫描
```bash
./onvif -cmd discover -ip 192.168.1.100
```

#### 2. 网段扫描
```bash
./onvif -cmd discover -ip 192.168.1.0/24
./onvif -cmd discover -ip 10.0.0.0/16
```

#### 3. 自动全网扫描
```bash
./onvif -cmd discover -ip auto -timeout 10000
```

#### 4. 多网段扫描
```bash
./onvif -cmd discover -ip "192.168.1.0/24,10.0.0.0/24,172.16.0.0/24"
```

### 设备信息查询

#### 获取设备详细信息
```bash
./onvif -cmd info -host http://192.168.1.100/onvif/device_service -user admin -pass 123456
```

#### 获取媒体配置
```bash
./onvif -cmd media -host http://192.168.1.100/onvif/device_service -user admin -pass 123456
```

#### 获取PTZ功能
```bash
./onvif -cmd ptz -host http://192.168.1.100/onvif/device_service -user admin -pass 123456
```

## 🔐 安全测试功能

### 弱口令字典配置

创建自定义凭据文件 `my_passwords.txt`：
```
# ONVIF摄像头弱口令字典
# 格式: 用户名:密码

# 空密码测试
admin:
root:

# 默认密码
admin:admin
admin:123456
admin:password
admin:888888

# 厂商默认
hikvision:hikvision
dahua:dahua
uniview:uniview

# 常见弱密码
admin:admin123
admin:1qaz2wsx
user:user
guest:guest
operator:operator

# 自定义密码...
```

### 使用自定义字典
```bash
./onvif -cmd discover -ip 192.168.1.0/24 -creds my_passwords.txt -output scan_results.json
```

### 安全报告示例

#### 控制台输出
```
=== COMPREHENSIVE SECURITY SUMMARY ===
Total devices found: 5

ONVIF Security:
  Devices with weak ONVIF credentials: 2
  Devices with no ONVIF authentication: 1

RTSP Security:
  Devices with weak RTSP credentials: 3
  Devices with no RTSP authentication: 1

⚠️  CRITICAL: 7 protocol vulnerabilities found across devices!
   - ONVIF vulnerabilities: 3
   - RTSP vulnerabilities: 4
```

#### JSON输出格式
```json
{
  "scan_time": "2024-01-01T12:00:00Z",
  "total_devices": 5,
  "security_summary": {
    "onvif_security": {
      "devices_with_weak_auth": 2,
      "devices_with_no_auth": 1,
      "vulnerable_devices": 3
    },
    "rtsp_security": {
      "devices_with_weak_auth": 3,
      "devices_with_no_auth": 1,
      "vulnerable_devices": 4
    },
    "total_vulnerabilities": 7,
    "critical_devices": 2
  },
  "devices": [
    {
      "ip": "192.168.1.100",
      "port": 80,
      "manufacturer": "Hikvision",
      "model": "DS-2CD2142FWD-I",
      "serial_number": "DS-2CD2142FWD-I12345678",
      "firmware_version": "V5.5.0",
      "auth_status": "weak_auth",
      "weak_password": true,
      "rtsp_auth_status": "weak_auth",
      "rtsp_weak_password": true,
      "rtsp_streams": [
        "rtsp://192.168.1.100:554/Streaming/Channels/101",
        "rtsp://192.168.1.100:554/live"
      ],
      "capabilities": {
        "ONVIF": true,
        "RTSP": true,
        "PTZ": true,
        "Recording": true
      },
      "services": {
        "ONVIF": "http://192.168.1.100/onvif/device_service",
        "RTSP": "rtsp://192.168.1.100:554/",
        "Media": "http://192.168.1.100/onvif/media_service"
      }
    }
  ]
}
```

## 🎯 典型应用场景

### 1. 企业网络安全审计
```bash
# 全面扫描企业网络
./onvif -cmd discover -ip "192.168.0.0/16,10.0.0.0/8" -output enterprise_audit.json -timeout 20000
```

### 2. 渗透测试
```bash
# 使用大型密码字典进行测试
./onvif -cmd discover -ip 172.16.0.0/12 -creds pentest_passwords.txt -output pentest_results.json
```

### 3. 物联网设备清单
```bash
# 发现并记录所有网络摄像头
./onvif -cmd discover -ip auto -output iot_inventory.json -timeout 30000
```

### 4. 应急响应
```bash
# 快速识别未授权访问风险
./onvif -cmd discover -ip 192.168.1.0/24 -timeout 5000
```

## 🔍 支持的设备厂商

### 完全支持
- **海康威视 (Hikvision)** - 完整ONVIF + RTSP支持
- **大华技术 (Dahua)** - 包含专有流格式
- **宇视科技 (Uniview)** - 全功能支持
- **Axis Communications** - 标准ONVIF支持
- **Bosch Security** - 企业级设备支持

### 部分支持
- Sony, Samsung, Panasonic
- Vivotek, Foscam, D-Link
- TP-Link, 通用IP摄像头

## ⚡ 性能优化

### 并发控制
- **TCP扫描**: 最大100并发连接
- **WS-Discovery**: 最大50并发查询
- **RTSP测试**: 智能限流防止网络拥塞

### 超时设置建议
- **局域网扫描**: 3000-5000ms
- **跨网段扫描**: 8000-15000ms
- **大型网络**: 20000-30000ms

## 🚨 使用注意事项

### 法律合规
- 仅用于授权网络的安全测试
- 遵守当地网络安全法律法规
- 不得用于未授权的网络扫描

### 网络影响
- 大规模扫描可能影响网络性能
- 建议在维护窗口期进行
- 使用适当的超时和并发设置

### 隐私保护
- 扫描结果可能包含敏感信息
- 妥善保管输出文件
- 及时修复发现的安全漏洞

## 🔧 开发相关

### 编译要求
- Go 1.13+
- 支持 Windows, Linux, macOS

### 跨平台编译
```bash
# 使用内置编译脚本
./build.sh

# 手动编译特定平台
GOOS=linux GOARCH=arm64 go build ./cmd/onvif
GOOS=windows GOARCH=amd64 go build ./cmd/onvif
```

### 移动端集成
```bash
# Android AAR
make build

# iOS Framework  
make build_ios
```

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 📞 技术支持

- GitHub Issues: [https://github.com/quocson95/go-onvif/issues](https://github.com/quocson95/go-onvif/issues)
- 文档: 查看 [CLAUDE.md](CLAUDE.md) 获取开发者文档

---

**⚡ 现在就开始使用吧！**

```bash
./onvif -cmd discover -ip auto -output my_scan.json
```