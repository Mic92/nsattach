# Fork of nsenter from util-linux with pseudo tty support

## Build

```
./autogen.sh && ./configure && make && make install
```

On archlinux you can install [nsenter-pty](https://aur.archlinux.org/packages/nsenter-pty/) from AUR

## Usage

```
nsenter-pty --target <NAMESPACE_IP> --mount --uts --ipc --net --pid --pty bash
[root@base /]# tty
/dev/pts/0
```

### without pty

```
nsenter-pty --target <NAMESPACE_IP> --mount --uts --ipc --net --pid bash
[root@base /]# tty
not a tty
```
