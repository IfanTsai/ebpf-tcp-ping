package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
)

const pingPort = "65532"

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <linux/inet.h>

typedef struct {
    u64 ts_ns;
} tcp_start_info_t;

typedef struct {
    u64 daddr;
    u64 delta_us;
} rtt_t;

BPF_HASH(tcp_start_infos, struct sock *, tcp_start_info_t);
BPF_PERF_OUTPUT(ping_events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *skp)
{
    tcp_start_info_t info;
    info.ts_ns = bpf_ktime_get_ns();
    tcp_start_infos.update(&skp, &info);

    return 0;
};

int kprobe__tcp_reset(struct pt_regs *ctx, struct sock *sk)
{
    tcp_start_info_t *info = tcp_start_infos.lookup(&sk);
    if (unlikely(!info))
        return 0;

    u16 family = sk->__sk_common.skc_family;
    u16 dport = bpf_ntohs(sk->__sk_common.skc_dport);

    if (likely(AF_INET == family && PINGPORT == dport)) {
        u64 daddr = bpf_ntohl(sk->__sk_common.skc_daddr);
        u64 ts = info->ts_ns;
        u64 now = bpf_ktime_get_ns();
        u64 delta_us = (now - ts) / 1000ul;

        rtt_t rtt;
        rtt.daddr = daddr;
        rtt.delta_us = delta_us;

        ping_events.perf_submit(ctx, &rtt, sizeof(rtt));
    }

    tcp_start_infos.delete(&sk);

    return 0;
}
`

type pingEventType struct {
	Daddr   uint64
	DeltaUs uint64
}

func loadKporbe(m *bpf.Module, name string) {
	probe, err := m.LoadKprobe("kprobe__" + name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %s\n", name, err)
		os.Exit(1)
	}

	if err = m.AttachKprobe(name, probe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach %s: %s\n", name, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf("Usage: %v <ip>\n", os.Args[0])
	fmt.Printf("e.g.: %v 172.217.194.106\n", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	ip := os.Args[1]

	m := bpf.NewModule(source, []string{
		"-w",
		"-DPINGPORT=" + pingPort,
	})

	defer m.Close()

	loadKporbe(m, "tcp_v4_connect")
	loadKporbe(m, "tcp_reset")

	pingEvent := bpf.NewTable(m.TableId("ping_events"), m)
	pingEventCh := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(pingEvent, pingEventCh, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Runing ping program, hit CTRL+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event pingEventType
		for {
			data := <-pingEventCh
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			fmt.Printf("tcp RST from %s: time=%.3f ms\n", ip, float64(event.DeltaUs)/1000.0)
		}
	}()

	go func() {
		for {
			_, err := net.Dial("tcp", ip+":"+pingPort)
			if err != nil {
				errStr := err.Error()
				if !strings.Contains(errStr, "connection refused") {
					fmt.Println("net.Dial error: " + errStr)
					sig <- os.Interrupt
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
