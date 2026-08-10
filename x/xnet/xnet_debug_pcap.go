//go:build xnetdebug

package xnet

import (
	"os"

	"github.com/xinix00/lneto/internal"
)

var _pcap CapturePrinter

func init() {
	_pcap.Configure(os.Stdout, CapturePrinterConfig{
		NamespaceWidth: 3,
	})
}

func debugPacket(msg string, b []byte) {
	_pcap.PrintEthernet(msg, b)
	if internal.HeapAllocDebugging {
		internal.LogAllocs(msg)
	}
}
