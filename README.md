# Fork of nsenter from util-linux with pseudo tty support

## Build

```
./autogen.sh && ./configure && make
```

## Usage

```
sudo ./nsenter-pty --target <NAMESPACE_IP> --mount --uts --ipc --net --pid --pty bash
[root@base /]# tty
/dev/pts/0
```

### without pty

```
sudo ./nsenter-pty --target <NAMESPACE_IP> --mount --uts --ipc --net --pid bash
[root@base /]# tty
not a tty
```
