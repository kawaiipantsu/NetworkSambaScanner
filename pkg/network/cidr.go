package network

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ExpandCIDR returns all usable host IP addresses for a given CIDR notation.
// For a /32 it returns that single address; for larger blocks it omits
// network and broadcast addresses.
func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Maybe it's a plain IP address
		if plain := net.ParseIP(cidr); plain != nil {
			return []string{plain.String()}, nil
		}
		return nil, fmt.Errorf("invalid CIDR or IP %q: %w", cidr, err)
	}

	// Determine prefix length
	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return nil, fmt.Errorf("unsupported IP version for %q", cidr)
	}

	// /32 (IPv4) or /128 (IPv6) – single host
	if ones == bits {
		return []string{ip.String()}, nil
	}

	var ips []string
	start := ipToUint32(ipNet.IP)
	end := start | ^maskToUint32(ipNet.Mask)

	// Skip network (start) and broadcast (end) for IPv4 /31 and larger
	from := start + 1
	to := end - 1
	if ones >= 31 {
		// /31 and /32 subnets – all addresses are usable (RFC 3021)
		from = start
		to = end
	}

	for i := from; i <= to; i++ {
		ips = append(ips, uint32ToIP(i).String())
	}
	return ips, nil
}

// ExpandRanges expands a slice of CIDR/IP strings into a deduplicated list of
// individual IP strings.
func ExpandRanges(ranges []string) ([]string, error) {
	seen := make(map[string]struct{})
	var result []string
	for _, r := range ranges {
		hosts, err := ExpandCIDR(r)
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			if _, dup := seen[h]; !dup {
				seen[h] = struct{}{}
				result = append(result, h)
			}
		}
	}
	return result, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func maskToUint32(mask net.IPMask) uint32 {
	return binary.BigEndian.Uint32(mask)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
