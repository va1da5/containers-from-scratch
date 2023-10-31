# 🐳 Containers from Scratch

These are my personal research notes on attempting to replicate container functionality using generic Linux tools. The objective was to gain a comprehensive understanding of the underlying mechanisms and core functionality of containers.

## Journey

### Linux Host

```bash
# start virtual machine
vagrant up

# login into machine
vagrant ssh

sudo apt update && sudo apt install -y curl jq archivemount cgroup-tools

```

### Container File System

```bash
# container image name
export IMAGE=alpine
# create directory for storing image root filesystem
export CONTAINER_FS=$PWD/containers/$IMAGE/overlayfs
mkdir -p $CONTAINER_FS

# get an authorization token for public access
export TOKEN=\
"$(curl \
--silent \
--header 'GET' \
"https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/${IMAGE}:pull" \
| jq -r '.token' \
)"

# pull an image manifest and review its content
curl \
--silent \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
"https://registry-1.docker.io/v2/library/${IMAGE}/manifests/latest" \
| jq '.'


# pull an image manifest and extract the blob sums
curl \
--silent \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
"https://registry-1.docker.io/v2/library/${IMAGE}/manifests/latest" \
| jq -r '.fsLayers[].blobSum'

# set specific blob sum
export BLOBSUM=sha256:96526aa774ef0126ad0fe9e9a95764c5fc37f409ab9e97021e7b4775d82bf6fa

# get specific blob
curl \
--silent \
--location \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
"https://registry-1.docker.io/v2/library/${IMAGE}/blobs/${BLOBSUM}" \
> "$CONTAINER_FS/${BLOBSUM/*:/}.gz";


## alternatively
## write all of the blob sums to a file
curl \
--silent \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
"https://registry-1.docker.io/v2/library/${IMAGE}/manifests/latest" \
| jq -r '.fsLayers[].blobSum' > "$CONTAINER_FS/blobsums.txt"

## download all of the layer blobs from the manifest
while read BLOBSUM; do
curl \
--silent \
--location \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
"https://registry-1.docker.io/v2/library/${IMAGE}/blobs/${BLOBSUM}" \
> "$CONTAINER_FS/${BLOBSUM/*:/}.gz"; \
done < "$CONTAINER_FS/blobsums.txt"


## review layers and find one with rootfs
## this guide does not cover how to merge different layers
ls -la
total 3372
drwxr-x---  5 vagrant vagrant    4096 Oct 24 17:51 .
drwxr-xr-x  3 root    root       4096 Mar 29  2023 ..
-rw-rw-r--  1 vagrant vagrant 3401967 Oct 24 17:48 96526aa774ef0126ad0fe9e9a95764c5fc37f409ab9e97021e7b4775d82bf6fa.gz   # <-- contains rootfs
-rw-rw-r--  1 vagrant vagrant      32 Oct 24 17:48 a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.gz


# create directory for storing image root filesystem
mkdir -p $CONTAINER_FS/lower

# extract root filesystem from the container layer
tar -xvf "$CONTAINER_FS/${BLOBSUM/*:/}.gz" -C $CONTAINER_FS/lower

# alternatively

# mount the archive to the directory without extracting its contents
archivemount "$CONTAINER_FS/${BLOBSUM/*:/}.gz" $CONTAINER_FS/lower
```

### OverlayFS

```bash
# create directories needed for the different layers
# - the lower directory can be read-only or could be an overlay itself
# - the upper directory is normally writable. Stores changes in rootfs
# - the workdir is used to prepare files as they are switched between the layers
# - merged (rootfs) contains all files merges from different layers

mkdir -p $CONTAINER_FS/upper $CONTAINER_FS/work $CONTAINER_FS/rootfs

sudo mount -t overlay overlay -o lowerdir=$CONTAINER_FS/lower,upperdir=$CONTAINER_FS/upper,workdir=$CONTAINER_FS/work \
    $CONTAINER_FS/rootfs

```

### chroot Jail

```bash
export ROOTFS=$CONTAINER_FS/rootfs

# chroot allows to restrict a process’ view of the file system
sudo chroot $ROOTFS /bin/sh

# review processes
ps -a

# mount proc
mount -t proc proc /proc

# review all available processes
ps -a

# attempt to kill some process that is running on host
pkill top
```

### Namespaces

```bash
export ROOTFS=$CONTAINER_FS/rootfs

# namespaces allow to create restricted views of systems like the process tree, network interfaces, and mounts
# the below creates a PID namespace for the shell, then execute the chroot as seen previously
unshare -p -f --mount-proc=$ROOTFS/proc -- \
    chroot $ROOTFS /bin/sh

# review process list
# pay attention to the process ID values
ps -a

# From the host, not the chroot.
ps -ax | grep /bin/sh
#    2818 pts/0    S+     0:00 sudo unshare -p -f --mount-proc=/mnt/rootfs/alpine/proc chroot /mnt/rootfs/alpine /bin/sh
#    2819 pts/1    Ss     0:00 sudo unshare -p -f --mount-proc=/mnt/rootfs/alpine/proc chroot /mnt/rootfs/alpine /bin/sh
#    2820 pts/1    S      0:00 unshare -p -f --mount-proc=/mnt/rootfs/alpine/proc chroot /mnt/rootfs/alpine /bin/sh
#    2821 pts/1    S+     0:00 /bin/sh

# list all linked namespaces for the process running in chroot jail
sudo ls -l /proc/2821/ns
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 cgroup -> 'cgroup:[4026531835]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 ipc -> 'ipc:[4026531839]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 mnt -> 'mnt:[4026532277]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 net -> 'net:[4026531840]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 pid -> 'pid:[4026532278]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 pid_for_children -> 'pid:[4026532278]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 time -> 'time:[4026531834]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 time_for_children -> 'time:[4026531834]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 user -> 'user:[4026531837]'
# lrwxrwxrwx 1 root root 0 Oct 26 16:00 uts -> 'uts:[4026531838]'

sudo nsenter --pid=/proc/2821/ns/pid \
     unshare -f --mount-proc=$ROOTFS/proc \
     chroot $ROOTFS /bin/sh

# list available processes
ps -a
# PID   USER     TIME  COMMAND
#     1 root      0:00 /bin/sh
#     8 root      0:00 unshare -f --mount-proc=/mnt/rootfs/alpine/proc chroot /mnt/rootfs/alpine /bin/sh
#     9 root      0:00 /bin/sh
#    11 root      0:00 ps -a
```

### Container Mounts

```bash
export ROOTFS=$CONTAINER_FS/rootfs

# create directory and file which will get mounted to container
mkdir readonlyfiles
echo "Hello, container!" > readonlyfiles/hello.txt

# mount the directory
mkdir -p $ROOTFS/var/readonlyfiles
mount --bind -o ro $PWD/readonlyfiles $ROOTFS/var/readonlyfiles

# start new process
unshare -p -f --mount-proc=$ROOTFS/proc \
    chroot $ROOTFS /bin/sh

# read the contents of the file
cat /var/readonlyfiles/hello.txt

# umount the directory from host CLI
umount $ROOTFS/var/readonlyfiles
```

### Control Groups v2

#### Manual Configuration

```bash
# list all possible cgroups
ls /sys/fs/cgroup/

# list all cgroups
lscgroup

# create a new cgroup2 for memory management
sudo mkdir -p /sys/fs/cgroup/demo/tasks

# list contents of the newly created cgroup
# ls -la /sys/fs/cgroup/memory/demo/
ls -la /sys/fs/cgroup/demo/

# define memory limitations and turn off swap
echo 50M | sudo tee /sys/fs/cgroup/demo/memory.max
echo "0" | sudo tee /sys/fs/cgroup/demo/memory.swap.max

echo "+cpu"  | sudo tee -a /sys/fs/cgroup/demo/cgroup.subtree_control
echo "+cpuset" | sudo tee -a /sys/fs/cgroup/demo/cgroup.subtree_control
echo "+memory" | sudo tee -a /sys/fs/cgroup/demo/cgroup.subtree_control

echo "max 100000" | sudo tee /sys/fs/cgroup/demo/tasks/cpu.max
echo "1" | sudo tee /sys/fs/cgroup/demo/tasks/cpuset.cpus
echo "5" | sudo tee /sys/fs/cgroup/demo/pids.max

# write own process ID to the task file from where tracking is being applied
echo $$ | sudo tee /sys/fs/cgroup/demo/tasks/cgroup.procs

# make process to run out of memory
tail /dev/zero

# drop fork bomb
:(){ :|: & };:
```

#### Cgroup for Container

```bash
export ROOTFS=$CONTAINER_FS/rootfs

# create cgroup for container
sudo cgcreate -g cpu,memory,pids,cpuset:container

# get current values
cgget -r memory.max container
cgget -r cpu.max container
cgget -r pids.max container

# set memory limit
# set memory limit
sudo cgset -r memory.max=128M container
sudo cgset -r cpu.max=100000 container
sudo cgset -r cpuset.cpus=1 container
sudo cgset -r pids.max=10 container
sudo cgset -r memory.swap.max=0 container

# test the limitations in a new bash process
sudo cgexec -g cpu,memory,pids,cpuset:container /bin/bash

# make process to run out of memory
tail /dev/zero

# mount the following if not already mounted
mount -t proc proc $ROOTFS/proc
mount -t tmpfs tmpfs $ROOTFS/tmp/
mount -t sysfs sysfs $ROOTFS/sys/

# cannot to get it working in Ubuntu 22.04
mknod -m 666 $ROOTFS/dev/zero c 1 5

echo 'nameserver 1.1.1.1' | tee $ROOTFS/etc/resolv.conf

# could not get this working due to user_namespace issues
sudo cgexec -g cpu,memory,pids,cpuset:container \
    unshare --mount \
        --uts \
        --ipc \
        --pid \
        --fork \
        --time \
        --user \
        --map-root-user \
        --mount-proc=$ROOTFS/proc \
    chroot $ROOTFS /bin/sh

export IMAGE=alpine
export CONTAINER_FS=$PWD/containers/$IMAGE/overlayfs
export ROOTFS=$CONTAINER_FS/rootfs
sudo cgexec -g cpu,memory,pids,cpuset:container \
    unshare \
        --mount \
        --uts \
        --ipc \
        --pid \
        --fork \
        --time \
        --net=/var/run/netns/container \
        --mount-proc=$ROOTFS/proc \
    chroot $ROOTFS /bin/sh

export IMAGE=alpine
export CONTAINER_FS=$PWD/containers/$IMAGE/overlayfs
export ROOTFS=$CONTAINER_FS/rootfs
sudo cgexec -g cpu,memory,pids,cpuset:container \
    unshare \
        --mount \
        --uts \
        --ipc \
        --pid \
        --fork \
        --time \
        --mount-proc=$ROOTFS/proc \
    ip netns exec container \
    chroot $ROOTFS /bin/sh

# attach to container by PID
sudo cgexec -g cpu,memory,pids,cpuset:container \
    nsenter -a -t $(ps -ax | grep "/bin/sleep infinite" | awk '!/grep|unshare/ {print $1}') \
    chroot $ROOTFS /bin/sh

# make process to run out of memory
tail /dev/zero

# drop fork bomb
:(){ :|: & };:
```

### Networking

```bash
# enables IP forwarding, which allows the system to forward packets between network interfaces
echo 1 | tee /proc/sys/net/ipv4/ip_forward

# creates a bridge interface named br0
ip link add name br0 type bridge

# brings up the br0 interface
ip link set br0 up

# assigns the IP address 172.31.0.1 to the br0 interface
ip a add dev br0 172.31.0.1/24

# creates a pair of virtual Ethernet devices (veth0 and ceth0) that are linked together
ip l add veth0 type veth peer name ceth0

ip netns add container

# only when container is active
# creates a symbolic link to the network namespace of the container
# ln -s /proc/$(lsns | grep unshare | grep ' net ' | awk '{print $4}')/ns/net /var/run/netns/container

# moves the ceth0 interface into the network namespace of the container
ip l set ceth0 netns container

# brings up the veth0 interface
ip l set veth0 up

# brings up the ceth0 interface inside the container's network namespace
ip netns exec container ip l set ceth0 up

# adds veth0 to the br0 bridge
brctl addif br0 veth0

# assigns the IP address 172.31.0.2 to the ceth0 interface inside the container
ip netns exec container ip a add dev ceth0 172.31.0.2/24

# sets up the default route inside the container to use 172.31.0.1 as the gateway
ip netns exec container ip route add default via 172.31.0.1

# flushes all the rules in the iptables filter table
iptables -F

# flushes all the rules in the nat table
iptables -t nat -F

# sets up NAT for packets going out of the eth0 interface for the 172.31.0.0/24 subnet
iptables -t nat -A POSTROUTING -o eth0 -s 172.31.0.0/24 -j MASQUERADE

# verify NAT Rules
iptables -t nat -L
```

## References

- [Cgroups, namespaces, and beyond: what are containers made from?](https://www.youtube.com/watch?v=sK5i-N34im8&ab_channel=Docker)
- [Containers unplugged: Linux namespaces - Michael Kerrisk](https://www.youtube.com/watch?v=0kJPa-1FuoI&ab_channel=NDCConferences)
- [Michael Kerrisk :: Understanding Linux user namespaces](https://www.youtube.com/watch?v=XgThPoL9mPE&ab_channel=CoreCppIL)
- [Digging into Linux namespaces - part 1](https://blog.quarkslab.com/digging-into-linux-namespaces-part-1.html)
- [Digging into Linux namespaces - part 2](https://blog.quarkslab.com/digging-into-linux-namespaces-part-2.html)
- [Containers from Scratch](https://ericchiang.github.io/post/containers-from-scratch/)
- [Downloading Docker Images from Docker Hub without using Docker](https://devops.stackexchange.com/questions/2731/downloading-docker-images-from-docker-hub-without-using-docker)
- [Rootless Containers from Scratch - Liz Rice, Aqua Security](https://www.youtube.com/watch?v=jeTKgAEyhsA&ab_channel=TheLinuxFoundation)
- [cgroup memory](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/resource_management_guide/sec-memory#memory_example-usage)
- [Using cgroups-v2 to control distribution of CPU time for applications](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/using-cgroups-v2-to-control-distribution-of-cpu-time-for-applications_managing-monitoring-and-updating-the-kernel)
- [Using cgroups to defeat fork bombs](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-4/#using-cgroups-to-defeat-fork-bombs)
- [Containers 101 - From Scratch](https://github.com/AlexonOliveiraRH/containers101)
- [Understanding and Working with the Cgroups Interface - Michael Anderson, The PTR Group, LLC](https://www.youtube.com/watch?v=z7mgaWqiV90&ab_channel=TheLinuxFoundation)
- [Starting a Process in a Control Group](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/resource_management_guide/starting_a_process)
- [Overlay filesystem](https://wiki.archlinux.org/title/Overlay_filesystem)
- [How to Use mknod Command in Linux](https://distroid.net/mknod-command-linux/)
- [mknod Devices](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/admin-guide/devices.txt)
- [How Docker Works - Intro to Namespaces](https://www.youtube.com/watch?v=-YnMr1lj4Z8&ab_channel=LiveOverflow)
- [Namespaces in operation, part 7: Network namespaces](https://lwn.net/Articles/580893/)
- [ip-netns](https://man7.org/linux/man-pages/man8/ip-netns.8.html)
