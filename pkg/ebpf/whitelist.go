package ebpf

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

// add ip vào whitelist map
func (l *Loader) AddToWhitelist(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("địa chỉ IP không hợp lệ: %s", ipStr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("chỉ hỗ trợ IPv4: %s", ipStr)
	}

	// ip to u32 (network byte order)
	val := binary.LittleEndian.Uint32(ipv4)

	now := uint64(time.Now().UnixNano())

	whitelistMap := l.GetMap("whitelist")
	if whitelistMap == nil {
		return fmt.Errorf("không tìm thấy whitelist map")
	}

	err := whitelistMap.Update(val, now, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("lỗi khi cập nhật whitelist: %v", err)
	}

	return nil
}

// xóa ip từ whitelist map
func (l *Loader) RemoveFromWhitelist(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("địa chỉ IP không hợp lệ: %s", ipStr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("chỉ hỗ trợ IPv4: %s", ipStr)
	}

	val := binary.LittleEndian.Uint32(ipv4)

	whitelistMap := l.GetMap("whitelist")
	if whitelistMap == nil {
		return fmt.Errorf("không tìm thấy whitelist map")
	}

	err := whitelistMap.Delete(val)
	if err != nil {
		return fmt.Errorf("lỗi khi xóa whitelist: %v", err)
	}

	return nil
}

// đọc và nạp ip từ file txt
func (l *Loader) LoadWhitelistFromFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("không thể mở file: %v", err)
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		err := l.AddToWhitelist(line)
		if err == nil {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("lỗi khi đọc file: %v", err)
	}

	return count, nil
}
