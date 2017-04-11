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

A tool, `fluxtop`, is included to watch the rx/tx rates in a top-like manner.
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

In the top-level fluxcap directory, run:

    git submodule update --init --recursive
    ./autogen.sh
    ./configure
    make
    sudo make install

This places `fluxcap`, `fluxtop` and `ramdisk` in the default bindir,
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
offloading solves these problems.

Optionally, iptables(8) can be set up to drop all input and output packets on
the interfaces that fluxcap is receiving and transmitting on. This prevents the
small fluff of background traffic that system components generate on
unconfigured interfaces, and keeps the system from reacting to the tap traffic.

    /sbin/iptables -A INPUT -i $IF -j DROP
    /sbin/iptables -A OUTPUT -o $IF -j DROP

### Tap replication 

Suppose you have a quad-NIC server, to be used in this way:

    eth0: management network
    eth1: network tap (INPUT)
    eth2: network tap replicate #1 (OUTPUT)
    eth3: network tap replicate #2 (OUTPUT)

This is how you would set up this arrangement using fluxcap:

    mkdir /ramdisk
    ramdisk -c -s 1g /ramdisk      # mount a 1 gb tmpfs ramdisk
    cd /ramdisk

    fluxcap -cr -s 100m i1 o1 o2   # create ring buffers of size 100m
    fluxcap -rx -i eth1 i1 &       # capture from eth1 into i1
    fluxcap -T i1 o1 o2 &          # tee i1 to o1 and o2
    fluxcap -tx -i eth2 o1 &       # transmit o1 on eth2
    fluxcap -tx -i eth3 o2 &       # transmit o2 on eth3

At this point you could use `fluxtop` to watch the I/O rates on the three
buffers.

    fluxtop i1 o1 o2

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
of them together and send them out another gigabit link. You can use `fluxtop`
to see the I/O rates and loss on the ring buffers.

A ring in fluxcap is meant to have one receiver and one transmitter. In other
words to transmit a ring on two NIC's, you need to "tee" it as shown.

A ring can be created on a regular disk filesystem rather than a ramdisk, but
this is not recommended except on low volume taps. (Internally, fluxcap maps
the ring buffers into shared memory between receivers and transmitters).

Based on experience it is advisable to keep a tmpfs ramdisk under 50% full.

#### Persistent operation

The examples above run the processes "by hand" on the command line.  In
practice these processes would be placed under the supervision of an init
manager.  I use [pmtr](http://troydhanson.github.io/pmtr/) for this purpose.

#### Encapsulation modes

Fluxcap can transmit packets over a routed/switched network too. This requires
use of one the encapsulation modes. The supported encapsulation modes are GRE,
GRETAP and ERSPAN.

    fluxcap -tx -E gre:192.168.102.100 tap     # GRE encapsulation
    fluxcap -tx -E gretap:192.168.102.100 tap  # GRETAP encapsulation
    fluxcap -tx -E erspan:192.168.102.100 tap  # ERSPAN encapsulation

On the remote (recipient) end, you can confirm the data is being received using:

    tcpdump -i eth0 -nne proto gre

You can take this a step further, and have a Linux recipient decapsulate the
GRE or GRETAP encapsulation. This results in Linux presenting a virtual NIC
with the decapsulated packets.

    # GRE decapsulation
    modprobe ip_gre
    ip tunnel add gre1 mode gre remote 192.168.102.1 local 192.168.102.100 ttl 255
    ip link set gre1 up
    tcpdump -i gre1 -nne

 If the fluxcap transmitter uses gretap ("transparent ethernet bridging") 
 encapsulation instead, which preserves MAC addresses in the encapsulation,
 it can be received this way instead:

    # GRETAP decapsulation
    modprobe ip_gre
    ip link add gretap1 type gretap local 192.168.102.100 remote 192.168.102.1
    ip link set gretap1 up
    tcpdump -i gretap1 -nne


