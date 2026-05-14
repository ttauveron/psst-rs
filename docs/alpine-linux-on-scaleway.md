# Install Alpine Linux On A Scaleway Stardust Instance With netboot.xyz

This guide describes a way to install Alpine Linux on a Scaleway Stardust instance without using a rescue image, by booting the Alpine installer over the network through netboot.xyz.

Inspiration source: karolba's gist, still relevant as of February 9, 2026. It describes UEFI/netboot.xyz booting from the Scaleway serial console. ([Gist][1])

## Prerequisites

You need:

- an existing Scaleway Stardust instance;
- the Scaleway `scw` CLI configured;
- the instance UUID;
- the instance zone, for example `fr-par-1`;
- access to the serial console;
- ideally a temporary IPv4 during installation, even if the final machine will be IPv6-only.

The installation can work in IPv6-only mode, but it is more fragile. UEFI boot, netboot.xyz, iPXE, and Alpine mirrors must all work correctly over IPv6. To avoid wasting time, it is simpler to attach a temporary IPv4 during installation, then remove it once Alpine is installed and SSH works over IPv6.

## 1. Open The Scaleway Serial Console

From your local machine:

```sh
scw instance server console <UUID> zone=<ZONE>
```

Example:

```sh
scw instance server console 11111111-1111-1111-1111-111111111111 zone=fr-par-1
```

The serial console is not an SSH connection. It gives you access to the VM display and keyboard input. If you land on an already installed Linux system, it may ask for a local login/password. For the bootloader or installer, it is mainly useful for interacting with the UEFI/iPXE menus.

## 2. Reboot The VM Into UEFI Settings

Two methods are possible.

From the VM, if the installed system allows it:

```sh
systemctl reboot --firmware
```

Or from your local machine:

```sh
scw instance server reboot <UUID> zone=<ZONE>
```

During reboot, watch the serial console and press `Esc` several times to enter the UEFI menus.

## 3. Configure UEFI HTTP Boot

In the UEFI menu, go to:

```text
Device Manager
→ Network Device List
→ <the network card>
→ HTTP Boot Configuration
→ Boot URI
```

Enter the following URI:

```text
http://boot.netboot.xyz/ipxe/netboot.xyz.efi
```

Save the configuration, then return to the main menu. You may need to press `Esc` several times to go back up through the menus.

## 4. Boot Into netboot.xyz

In the main UEFI menu, go to:

```text
Boot Manager
```

Then select the new HTTP boot entry you just created.

Wait for netboot.xyz to load.

## 5. Configure The Serial Console In netboot.xyz

Once inside the netboot.xyz interface, go to:

```text
Utilities (UEFI)
→ Kernel cmdline params
```

Add:

```text
console=ttyS0
```

This is important: it lets you see and use the Alpine installer from the serial console. The original gist also notes that `setup-alpine` detects this console and configures the installed system to use the serial console as well. ([Gist][1])

## 6. Start The Alpine Installer

Go back through the netboot.xyz menus, then select:

```text
Linux Network Installs (64-bit)
→ Alpine Linux
```

Choose a recent Alpine version, then start the installer.

You should reach a prompt like:

```text
Welcome to Alpine Linux
localhost login:
```

Log in as root:

```text
root
```

In the Alpine live environment, root may be accessible without a password depending on the image used.

## 7. Check Networking

Before installing, verify that the VM has working network access:

```sh
ip addr
ip route
ip -6 route
ping -c 3 1.1.1.1
ping -6 -c 3 2606:4700:4700::1111
ping -6 -c 3 dl-cdn.alpinelinux.org
```

If you are in IPv6-only mode and DNS resolution fails, check:

```sh
cat /etc/resolv.conf
```

If the file only contains IPv4 DNS servers, for example:

```text
nameserver 51.159.69.156
nameserver 51.159.69.162
```

replace them temporarily with IPv6 DNS servers:

```sh
cat > /etc/resolv.conf <<'EOF'
nameserver 2606:4700:4700::1111
nameserver 2606:4700:4700::1001
nameserver 2001:4860:4860::8888
EOF
```

Then test again:

```sh
ping -6 -c 3 dl-cdn.alpinelinux.org
apk update
```

## 8. Identify The Disk

In the minimal live environment, `lsblk` may not be installed. You can add it:

```sh
apk update
apk add util-linux
lsblk
```

Or use:

```sh
cat /proc/partitions
fdisk -l
```

On Scaleway Stardust, the main disk is often:

```text
/dev/vda
```

Example:

```text
NAME    SIZE TYPE
vda     9.3G disk
├─vda1  ...
├─vda13 ...
├─vda14 ...
└─vda15 ...
```

The existing partitions probably come from the previous Scaleway image and can be erased if you are doing a clean installation.

## 9. Start The Alpine Installation

Run:

```sh
setup-alpine
```

Recommended answers:

```text
Hostname: your choice, for example psst
Interface: eth0
IP address: dhcp
Manual network configuration: n
Root password: choose a temporary password
Timezone: Europe/Zurich
Proxy: none
NTP client: chrony
APK mirror: choose the proposed mirror
SSH server: openssh
Disk: vda
Mode: sys
Erase disk: yes
```

The important mode is:

```text
sys
```

`sys` installs Alpine as a bootable system on disk. Do not choose `data` or `diskless` for this case.

If you have a temporary IPv4, still choose `dhcp` during installation. You can switch to IPv6-only after confirming that the installed system works.

## 10. Explicitly Add IPv6 To The Network Configuration

After installation, check the file:

```sh
cat /mnt/etc/network/interfaces
```

A simple configuration can be:

```text
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
iface eth0 inet6 auto
```

If `iface eth0 inet6 auto` is missing, add it.

This makes IPv6 autoconfiguration explicit. IPv4 DHCP can remain while the temporary IPv4 exists; it will simply stop getting an address once the IPv4 is removed.

## 11. Add Your SSH Key To The Installed System

Still from the live environment, add your SSH key to the installed system:

```sh
mkdir -p /mnt/root/.ssh
vi /mnt/root/.ssh/authorized_keys
chmod 700 /mnt/root/.ssh
chmod 600 /mnt/root/.ssh/authorized_keys
```

Paste your public key into `authorized_keys`.

You can also create a non-root user after the first boot, for example `ttauveron`, and put your SSH key there.

## 12. Reboot Into The Installed Alpine System

Reboot:

```sh
reboot
```

The instance should now boot into Alpine installed on `/dev/vda`.

Connect over SSH:

```sh
ssh root@<temporary-IPv4>
```

or over IPv6:

```sh
ssh root@[2001:bc8:....]
```

## 13. Post-Reboot Checks

On the installed VM:

```sh
cat /etc/alpine-release
uname -a
df -h
free -h
ip addr
ip -6 route
ping -6 -c 3 2606:4700:4700::1111
ping -6 -c 3 dl-cdn.alpinelinux.org
apk update
```

If IPv6 ping to an address works but domain names do not resolve, fix `/etc/resolv.conf` with IPv6 resolvers:

```sh
cat > /etc/resolv.conf <<'EOF'
nameserver 2606:4700:4700::1111
nameserver 2606:4700:4700::1001
nameserver 2001:4860:4860::8888
EOF
```

## 14. Secure SSH

Install and enable OpenSSH if it is not already installed:

```sh
apk add openssh
rc-update add sshd default
rc-service sshd start
```

Check or edit:

```sh
vi /etc/ssh/sshd_config
```

Recommended settings:

```text
PasswordAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
```

Then:

```sh
rc-service sshd restart
```

Before disabling password login, make sure SSH key authentication works.

## 15. Remove The Temporary IPv4

Only remove the temporary IPv4 once these three points are confirmed:

```text
1. The VM has a global IPv6 address.
2. The default IPv6 route works.
3. You can SSH to it from your local machine over IPv6.
```

Tests:

```sh
ip addr
ip -6 route
ping -6 -c 3 dl-cdn.alpinelinux.org
```

From your local machine:

```sh
ssh root@[<IPv6-de-la-VM>]
```

Once these tests pass, you can remove the temporary IPv4 on the Scaleway side.

After removing IPv4, reboot the VM or restart networking:

```sh
reboot
```

Then reconnect over IPv6.

## 16. Notes And Known Pitfalls

### IPv6-only

Final IPv6-only operation works well if Cloudflare sits in front of the service. IPv4 visitors talk to Cloudflare, and Cloudflare talks to the origin over IPv6.

On the other hand, netboot installation can be more fragile in IPv6-only mode. A temporary IPv4 makes installation much simpler.

### DNS After IPv4 Removal

After IPv4 removal, `/etc/resolv.conf` may still contain Scaleway IPv4 DNS servers. In that case, `apk update` fails with errors like:

```text
DNS: transient error
python3 (no such package)
```

This is not a real missing-package problem: DNS resolution is failing. Use IPv6 resolvers.

### Disque `/dev/vda`

If the disk already contains Scaleway partitions, that is normal. The `sys` mode of `setup-alpine` can erase them for a clean Alpine install.

### Possible Issue With The First Disk Sectors

A comment on the original gist mentions an old issue where Alpine could not write to the first 4 MiB of the disk in some cases, especially with block storage rather than local storage. The proposed workaround was to modify `/sbin/setup-disk` so partitions start at `4M` instead of `1M`. This appears to be contextual and may not apply to current Stardust instances, but it can be useful if `setup-disk` fails during partitioning. ([Gist][1])

## 17. Next Step

Once Alpine is installed and reachable over IPv6, you can move on to:

```text
- Cloudflare DNS configuration with a proxied AAAA record;
- NGINX or Caddy configuration;
- a Cloudflare Origin CA certificate;
- deployment of your Rust binary;
- restricting the Scaleway Security Group to Cloudflare IPs;
- permanent removal of the temporary IPv4.
```

[1]: https://gist.github.com/karolba/a3f1c5f8d50c67f5a19e6c8f38e53e12 "Install Alpine Linux on Scaleway Stardust without the rescue image using https://netboot.xyz · GitHub"
