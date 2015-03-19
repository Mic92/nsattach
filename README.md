# nsattach - attach to linux namespaces

Fork of nsenter from util-linux with pseudo tty support for interactive usage.

## Build

```
./autogen.sh && ./configure && make && make install
```

If you on a rescue mission and need this features quick, use the following
command to get a small static binary:

```
curl https://raw.githubusercontent.com/Mic92/nsattach/master/nsattach.c | gcc -O2 -s -static -o /tmp/nsattach -xc -
```

## Usage

```
nsattach --target <NAMESPACE_IP> --mount --uts --ipc --net --pid --pty bash
[root@base /]# tty
/dev/pts/0
```

### without pty

```
nsattach --target <NAMESPACE_IP> --mount --uts --ipc --net --pid bash
[root@base /]# tty
not a tty
```
