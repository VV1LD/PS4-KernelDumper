# Kernel Dumper for PS4

Suported firmwares

4.05
4.55
5.05

# Network Mode

Just change this in ```/include/defines.h``` to make compatible with your version

i.e 

```c
#define KERN_VER 455
```

Compile with your PC's IP listening on port 9023

On PC you can do to listen:
	socat - tcp-listen:9023 > kernelDump.bin

and to send:
	socat -u FILE:payload.bin TCP:"PS4 IP":9020

you can then trim out the socket prints or you can adapt it with 2 sockets, one for dumping, another for logging.

To compile you need to use an sdk with changes for latest fw support support, i have used https://github.com/xvortex/ps4-payload-sdk

# USB/Filesystem Mode

To dump the kernel image to the filesystem or USB stick either change/keep

```c
#define KERN_FILEPATH "/mnt/usb0/kdump.bin"
```

..to where ever you choose

and to use the USB method simply comment out this line in ```/include/defines.h```

```c
#define DEBUG_SOCKET
```

to send it is still:

	socat -u FILE:payload.bin TCP:"PS4 IP":9020


Have Fun! :)


