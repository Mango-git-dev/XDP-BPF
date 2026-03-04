package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Loader struct {
	coll  *ebpf.Collection
	iface string
}

// load và attach xdp
func LoadAndAttach(objPath string, ifaceName string) (*Loader, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("không thể nạp spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo collection: %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("không tìm thấy interface %s: %v", ifaceName, err)
	}

	// attach xdp
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["xdp_anti_ddos_core"],
		Interface: iface.Index,
	})
	if err != nil {
		return nil, fmt.Errorf("không thể attach XDP: %v", err)
	}

	_ = l // Link sẽ được quản lý để dọn dẹp sau này

	return &Loader{coll: coll, iface: ifaceName}, nil
}

func (l *Loader) GetMap(name string) *ebpf.Map {
	return l.coll.Maps[name]
}

func (l *Loader) Close() {
	l.coll.Close()
}
