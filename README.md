# Fork nsenter from util-linux with pseudo tty support

## Build

gcc -std=c99 -I include nsenter.c -o nsenter

## Usage

sudo ./nsenter --target <NAMESPACE_IP> --mount --uts --ipc --net --pid --pty bash
[root@base /]# tty
/dev/pts/0

### without pty

sudo ./nsenter --target <NAMESPACE_IP> --mount --uts --ipc --net --pid bash
[root@base /]# tty
not a tty
