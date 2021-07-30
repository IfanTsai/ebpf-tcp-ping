[中文](./README_CN.md)

# ebpf-tcp-ping

## introduction

tcp ping command tool based on xdp and ebpf

- xdp_ping.c: xdp program, it will be loaded to kernel or NIC, it can return tcp rst package before tcp syn package enters the kernel protocol stack

- tcp_ping.go: tcp ping command tool, it can send a tcp syn package to other server, and use the ebpf to hook kernel tcp status function to calculate RTT

## load xdp program to NIC

Please check your NIC in Makefile
```Makefile
NIC   ?= eth0
```

install and uninstall
```
make
sudo make install
sudo make uninstall
```

## ping other server

help

```
➜  sudo go run tcp_ping.go -h
tcp_ping version: 0.0.1
Usage: tcp_ping 172.217.194.106 [-d 500] [-c 100] [-s]

Options:
  -c Number
    	Number connections to keep ping (default 1)
  -d duration
    	Ping duration ms (default 1000)
  -h	Show help
  -s	Do not show information of each ping
```

Noted that port 65532 of other server shoule be opened
