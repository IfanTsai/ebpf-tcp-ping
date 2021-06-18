package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
)

/* command line arguments */
var (
	help        bool
	silent      bool
	duration    int
	connections int
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

func cmdLineInit() {
	flag.BoolVar(&help, "h", false, "Show help")
	flag.BoolVar(&silent, "s", false, "Do not show information of each ping")
	flag.IntVar(&duration, "d", 1000, "Ping `duration` ms")
	flag.IntVar(&connections, "c", 1, "`Number` connections to keep ping")

	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, "ping version: 0.0.1\nUsage: ping 172.217.194.106 [-d 500] [-c 100] [-s]\n\nOptions:\n")
	flag.PrintDefaults()
}

func main() {
	cmdLineInit()

	if len(os.Args) < 2 {
		flag.Usage()
		return
	}

	host := os.Args[1]

	os.Args = os.Args[1:]
	flag.Parse()

	if help || host == "" {
		flag.Usage()
		return
	}

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

	fmt.Println("Runing ping program, hit Ctrl + C to stop and count the results")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	var timeList []float64
	go func() {
		var event pingEventType
		for {
			data := <-pingEventCh
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			deltaMs := float64(event.DeltaUs) / 1000.0
			timeList = append(timeList, deltaMs)

			if !silent {
				fmt.Printf("tcp RST from %s: time=%.3f ms\n", host, deltaMs)
			}
		}
	}()

	for i := 0; i < connections; i++ {
		go func() {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, os.Kill)

			ticker := time.NewTicker(time.Duration(duration) * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-sig:
					return
				case <-ticker.C:
					_, err := net.Dial("tcp", host+":"+pingPort)
					if err != nil {
						errStr := err.Error()
						if !strings.Contains(errStr, "connection refused") {
							fmt.Println("net.Dial error: " + errStr)
							sig <- os.Interrupt
						}

					}

				}
			}
		}()
	}

	perfMap.Start()
	<-sig
	perfMap.Stop()

	times := len(timeList)

	var sumTimeMs float64
	for _, timeMs := range timeList {
		sumTimeMs += timeMs
	}

	fmt.Printf("\n\ntcp RST from %s: average time=%.3f ms\n", host, sumTimeMs/float64(times))
}
