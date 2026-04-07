# /dev/secret — Minix 3 Character Device Driver

A character device driver for Minix 3.1.8 that implements a `/dev/secret` interface for securely passing secrets between processes. Built as a course project for CPE 453 (Operating Systems) at Cal Poly.

## What it does

The driver exposes a single device file that can hold one secret at a time. Access is ownership-gated: the first process to open the device becomes the owner, and only the owner can read the secret back. Ownership can be transferred to another user via an `ioctl` call. The secret resets automatically once it has been read and all file descriptors are closed.

The driver is implemented entirely within the Minix kernel driver framework, with no HAL or standard libc IO — all memory transfers between the driver and user processes go through the kernel via `sys_safecopyto` and `sys_safecopyfrom`.

## What I learned

Working inside the Minix driver framework meant operating below the filesystem, which forced me to think carefully about things that higher-level code abstracts away. Buffer addresses passed in from user processes are virtual addresses in their address space, not the driver's, so every byte transfer has to be mediated by the kernel. The secret is also treated as raw bytes throughout — no string assumptions — since there is no guarantee the contents are null-terminated or printable.

The trickiest part was getting the reset condition right: the secret should persist after the writer closes, but once any read file descriptor has been opened, the secret wipes itself when the last fd closes. That required tracking not just an open count but whether a read fd had ever been opened during the current ownership cycle.

The project also gave me exposure to Minix's System Event Framework (SEF), including how to save and restore driver state across live update events using the data store.

## Usage

Build and install on a Minix 3.1.8 system:

```sh
# Create the device file (once)
mknod /dev/Secret c 20 0
chmod 666 /dev/Secret

# Register and start the driver
cd /usr/src/drivers/secret
make
service up /usr/sbin/secret -dev /dev/Secret
```

Writing and reading a secret:

```sh
echo "my secret" > /dev/Secret
cat /dev/Secret
```

Transferring ownership to another user (uid 13):

```c
int fd = open("/dev/Secret", O_WRONLY);
write(fd, msg, strlen(msg));
uid_t uid = 13;
ioctl(fd, SSGRANT, &uid);
close(fd);
```

See the README for a full list of changes required to the Minix source tree to wire up the driver and custom ioctl header.
