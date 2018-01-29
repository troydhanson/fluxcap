Back to the [fluxcap Github page](http://github.com/troydhanson/fluxcap). Back to [my other projects](http://troydhanson.github.io/).

# About

fluxcap: a network tap replication and aggregation tool

You can use fluxcap to receive network taps and replicate them, or to
aggregate network taps together and transmit the aggregated tap. The
only requirement is enough network interfaces (NICs) on the Linux host.

The taps come from 

 * SPAN ports or mirror ports on network switches, 
 * inline tap hardware, or 
 * tool ports on specialized hardware ("network packet brokers")

A tap is a stream of packets copied from some pathway or portion of the
network. The tapped packets are intended for out-of-band analysis (IDS
or other kinds of monitoring systems). Cabling a tap into a regular switch or
into a routed network is asking for trouble. A switch or router would inspect
the packet and egress it based on MAC or IP headers (potentially re-injecting
tapped data back into the network, disastrously, or at least failing to get
the packets reliably to the analysis hosts). As a result, separate methods
are used to direct taps to their destinations. These include the class of
devices known as network packet brokers, tap aggregation switches, etc.
In a simple world with one monitored switch and one analysis host, a cable
between them is enough. In a large enterprise with many switches, and many
analysis endpoints needing the tap data, tools to to collect, aggregate and
replicate taps and retransmit them in aggregate become helpful.

Fluxcap receives, replicates, aggregates, and transmits tap data based on 
command line arguments. It does this using raw sockets that bypass the usual
handling of TCP/IP packets in the kernel. In fact it is recommended to drop
all regular packet communication using `iptables` as shown below so that only
the raw socket can generate or respond to packets on the dedicated NICs.

An ncurses-based visual mode can be used to observe the ring I/O status.
Invoke it using `fluxcap -io <ring> ...` to monitor one or more rings.
No claims are made with regard to performance. Rates of 2-3 gigabit/sec
were used in development, and higher rates surely require improvements.

Fluxcap is written in C, MIT licensed, and for Linux only. 

Platforms: Ubuntu, RedHat, and probably most others. Yocto recipe 
[here](http://github.com/troydhanson/meta-fluxcap).

# Build & install

## Prereqs

On Ubuntu:

    sudo apt-get install git gcc automake autoconf libtool libncurses5-dev ethtool

On RHEL/CentOS:

    sudo yum install git gcc automake autoconf libtool ncurses-devel ethtool

## Build and install

### libshr

The libshr library must be built and installed prior to building fluxcap.

    git clone https://github.com/troydhanson/shr.git
    cd shr
    autoreconf -ivf
    ./configure
    make
    sudo make install
    cd ..

### fluxcap

In the top-level fluxcap directory, run:

    git submodule update --init --recursive
    ./autogen.sh
    ./configure
    make
    sudo make install

This places `fluxcap`, and `ramdisk` in the default bindir,
typically `/usr/local/bin`.

## Usage

The fluxcap binary should be run as root, because it uses raw sockets to 
capture traffic and emit traffic. 

### Prepare interfaces

A network interface used to capture or transmit data must be "up"- see ip(8).
It should not have an IP address. Hardware reassembly of IP fragments should be
disabled using ethtool(8). These commands seem to suffice; run them for each
interface used for receiving data.

    IF=eth1
    ethtool -K $IF tso off  # TCP segmentation offload (output)
    ethtool -K $IF ufo off  # UDP segmentation offload (output)
    ethtool -K $IF gso off  # generic segmentation offload (output)
    ethtool -K $IF gro off  # generic receive offload (input)
    ethtool -K $IF lro off  # large receive offload (input)

Disable receive offloading to keep the fragments as they were on the wire.  The
analysis endpoints want the packets in their original form. Hardware offloading
is the usual cause of "sendto" failures. (When offloading, the NIC can gather
IP fragments and present a large, single, reassembled IP datagram to the host.
While this datagram is a valid reconstruction, it cannot be retransmitted 
because it exceeds the MTU on the network. A regular TCP/IP socket would 
perform fragmentation automatically but raw sockets do not). Disabling
offloading solves these problems. An explanation of some offload parameters
can be found [here](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Performance_Tuning_Guide/network-nic-offloads.html).

Optionally, iptables(8) can be set up to drop all input and output packets on
the interfaces that fluxcap is receiving and transmitting on. This prevents the
small fluff of background traffic that system components generate on
unconfigured interfaces, and keeps the system from reacting to the tap traffic.

    /sbin/iptables -A INPUT -i $IF -j DROP
    /sbin/iptables -A OUTPUT -o $IF -j DROP

### Tap replication 

Suppose you have a quad-NIC server, to be used in this way:

    eth0: management network
    eth1: tap from vlan 1  (INPUT)
    eth2: tap replicate #1 (OUTPUT)
    eth3: tap replicate #2 (OUTPUT)

This is how you would set up this arrangement using fluxcap:

    mkdir /ramdisk
    ramdisk -c -s 1g /ramdisk      # mount a 1 gb tmpfs ramdisk
    cd /ramdisk

    fluxcap -cr -s 100m vlan1      # create ring buffer named vlan1
    fluxcap -rx -i eth1 vlan1 &    # capture from eth1 into vlan1
    fluxcap -tx -i eth2 vlan1 &    # transmit vlan1 on eth2
    fluxcap -tx -i eth3 vlan1 &    # transmit vlan1 on eth3

At this point you could use watch the I/O rates using `fluxcap -io`:

    fluxcap -io vlan1

### Tap aggregation

Suppose you have two tap inputs and want to aggregate them, and transmit
the aggregate tap on a third interface. This is the desired arrangement:

    eth0: management network
    eth1: network tap #1 (INPUT)
    eth2: network tap #2 (INPUT)
    eth3: aggregate tap (OUTPUT)

This is how you could set up this arrangement using fluxcap. We assume the
working directory is in a ramdisk as shown above.

    fluxcap -cr -s 100m i1 i2 o1   # create ring buffers of size 100m
    fluxcap -rx -i eth1 i1 &       # capture from eth1 into i1
    fluxcap -rx -i eth2 i2 &       # capture from eth1 into i1
    fluxcap -F o1 i1 i2 &          # funnel from i1/i2 to o1
    fluxcap -tx -i eth3 o1 &       # transmit o1 on eth3

### Tips

#### How big should the ring buffers be?

The size argument given to `-s` in a command such as 

    fluxcap -cr -s 100m buffer1 buffer2

specifies how large to make each ring buffer. (`100m` is a hundred megabytes,
`1g` is one gigabyte). A gigabyte can buffer about ten seconds of traffic
from a fully loaded gigabit interface. In normal circumstances a much smaller
ring suffices.  Since fluxcap transmits and receives continuously through the
ring buffer, it may be adequate to use a small buffer (say tens of megabytes).

#### VLAN tag injection

Fluxcap can insert synthetic VLAN (802.1q) tags on the packets as they arrive.
This can be used when subsequently aggregating taps to preserve knowledge of
the source.

    fluxcap -rx -i eth2 -V 100 i1 &  # tag each packet as from VLAN 100

#### Truncation

Packets can be truncated to a given length upon transmit using the `-s` option.

    fluxcap -tx -i eth3 -s 40 o1 &  # transmit first 40 bytes of each packet

#### Ring remarks

The examples above use names like `i1` or `o1` for input and output rings. In
practice it is probably better to use names like `dmz-input` or `snort-output`
for the rings so their function is more obvious.

If you aggregate two 1 gigabit/sec taps together, and attempt to retransmit
the resulting 2 gigabits/sec on another 1 gigabit/sec link, expect packet loss.

In reality, some gigabit links are barely utilized, and you can aggregate many
of them together and send them out another gigabit link. You can see the I/O
rates and loss on the ring buffers in an ncurses interface like this:

    fluxcap -io <ring> ...

In early versions of fluxcap, a ring could have one receiver and one transmitter. 
This required use of a "tee" (`-T` mode) to duplicate or triplicate a ring.
This is no longer necessary. Many fluxcap processes can read from one ring.

A ring should be created on a ramdisk (tmpfs filesystem) only, for performance.
Based on experience it is advisable to keep a tmpfs ramdisk under 50% full.

#### Persistent operation

The examples above run the processes "by hand" on the command line.  In
practice these processes would be placed under the supervision of an init
manager.  I use [pmtr](http://troydhanson.github.io/pmtr/) for this purpose.

#### Encapsulation modes

Fluxcap can transmit packets over a routed/switched network too. This requires
use of one the encapsulation modes. The supported encapsulation modes are GRE,
GRETAP and ERSPAN.  The GRETAP ("transparent ethernet bridging") encapsulation
preserves original MAC addresses in the encapsulation, and is preferred.

    fluxcap -tx -E gretap:192.168.102.100 tap  # GRETAP encapsulation (preferred)
    fluxcap -tx -E gre:192.168.102.100 tap     # GRE encapsulation
    fluxcap -tx -E erspan:192.168.102.100 tap  # ERSPAN encapsulation (untested)

It is recommended to use `-s 1476` with a a gretap transmitter to truncate packets
that would exceed the standard MTU when tunneled inside GRE.

On the remote (recipient) end, you can confirm the data is being received using:

    tcpdump -i eth0 -nne proto gre

This works for any of the encapsulations, since all three modes utilize GRE tunnels.

##### Decapsulation 

If the recipient host is Linux, you can have it decapsulate the data for you.
This results in Linux presenting a virtual NIC with the decapsulated packets.

    # GRETAP decapsulation
    modprobe ip_gre
    ip link add gretap1 type gretap local 192.168.102.100 remote 192.168.102.1
    ip link set gretap1 up
    tcpdump -i gretap1 -nne

You should replace 192.168.102.x with the actual local (recipient) and remote
(transmitter) IP addresses. 

Decapsulating plain GRE is similar.

    # GRE decapsulation
    modprobe ip_gre
    ip tunnel add gre1 mode gre remote 192.168.102.1 local 192.168.102.100 ttl 255
    ip link set gre1 up
    tcpdump -i gre1 -nne

You may need to ensure that iptables/firewalld allow the traffic. On a CentOS 7
system, `sudo systemctl stop firewalld` permits the data to arrive on gretap1.
