[English](./README.md)

# ebpf-tcp-ping

## 介绍

基于 xdp 和 ebpf 的 tcp ping 命令行工具

- xdp_ping.c: xdp 程序, 将会被加载到内核或网卡中， 在 tcp syn 包进入协议栈之前返回 tcp rst 包

- tcp_ping.go: tcp ping 命令行工具，它会发送 tcp syn 包给指定的服务器，并且使用 ebpf 去 hook 内核 tcp 状态转换的函数来计算 RTT

## 加载 xdp 程序到 NIC

请检查 Makefile 中的 NIC 变量
```Makefile
NIC   ?= eth0
```

安装和卸载 xdp 程序
```
make
sudo make install
sudo make uninstall
```

## ping 其他服务器

帮助

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

务必注意其他服务器的 65532 端口需要开放
