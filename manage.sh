#!/usr/bin/env bash

export IMAGE=alpine
export CONTAINER_FS=$PWD/containers/$IMAGE/overlayfs
export ROOTFS=$CONTAINER_FS/rootfs
export CONTAINER_BLOBSUM=sha256:96526aa774ef0126ad0fe9e9a95764c5fc37f409ab9e97021e7b4775d82bf6fa # Alpine rootfs

# install host dependencies
function get_dependencies(){
    apt update
    apt install -y curl jq archivemount cgroup-tools bridge-utils
}

# download container file system from Dockerhub
function get_fs(){
    # prepare directory structure
    mkdir -p $CONTAINER_FS/lower $CONTAINER_FS/upper $CONTAINER_FS/work $CONTAINER_FS/rootfs
    
    # get an authorization token for public access
    TOKEN="$(curl \
        --silent \
        --header 'GET' \
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/${IMAGE}:pull" \
        | jq -r '.token' \
    )"
    
    # get specific blob
    curl \
    --silent \
    --location \
    --request 'GET' \
    --header "Authorization: Bearer ${TOKEN}" \
    "https://registry-1.docker.io/v2/library/${IMAGE}/blobs/${CONTAINER_BLOBSUM}" \
    > "$CONTAINER_FS/${CONTAINER_BLOBSUM/*:/}.gz";
    
    tar -xvf "$CONTAINER_FS/${CONTAINER_BLOBSUM/*:/}.gz" -C $CONTAINER_FS/lower
}

# mount overlayfs container file system
function mount_fs(){
    mount -t overlay overlay -o lowerdir=$CONTAINER_FS/lower,upperdir=$CONTAINER_FS/upper,workdir=$CONTAINER_FS/work \
    $CONTAINER_FS/rootfs
}

# mount system related resources
function mount_sys_fs(){
    mknod -m 622 $ROOTFS/dev/console c 5 1
    mknod -m 666 $ROOTFS/dev/zero c 1 5
    mknod -m 666 $ROOTFS/dev/ptmx c 5 2
    mknod -m 666 $ROOTFS/dev/tty c 5 0
    mknod -m 444 $ROOTFS/dev/random c 1 8
    mknod -m 444 $ROOTFS/dev/urandom c 1 9
    chown -v root:tty $ROOTFS/dev/{console,ptmx,tty}
    
    ls -la $ROOTFS/dev/
    
    mount -t proc proc $ROOTFS/proc -o nosuid,noexec,nodev
    mount -t tmpfs tmpfs $ROOTFS/tmp/
    mount -t sysfs sysfs $ROOTFS/sys/ -o rw,nosuid,nodev,noexec,relatime
    
    mount | grep $ROOTFS
}

function umount_sys_fs(){
    umount $ROOTFS/proc
    umount $ROOTFS/tmp/
    umount $ROOTFS/sys/
    
    rm -rf $ROOTFS/dev/*
}

# create cgroup for containers
function cgroup(){
    # create cgroup for container
    cgcreate -t $USER:$USER -a $USER:$USER -g cpu,memory,pids,cpuset:container
    
    # set limits
    cgset -r memory.max=128M container
    cgset -r cpu.max=100000 container
    cgset -r cpuset.cpus=1 container
    cgset -r pids.max=10 container
    cgset -r memory.swap.max=0 container
    
    lscgroup | grep container
}

function network(){
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
    
    # only when container is active
    # creates a symbolic link to the network namespace of the container
    ln -s /proc/$(lsns | grep unshare | grep ' net ' | awk '{print $4}')/ns/net /var/run/netns/container
    
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
}

# provisioning workflow
function up(){
    get_dependencies
    get_fs
    mount_fs
    mount_sys_fs
    cgroup
}

function down(){
    umount_sys_fs
}

# execute function by name
$1
