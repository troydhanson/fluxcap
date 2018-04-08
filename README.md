Back to the [fluxcap Github page](http://github.com/troydhanson/fluxcap).
Back to [my other projects](http://troydhanson.github.io/).

# About

fluxcap: a network tap replication and aggregation tool

Network taps usually come from one of these sources:

 * SPAN ports or mirror ports
 * network packet brokers
 * inline taps

Once we have a tap- or many taps- we may want to:

 * copy the tap out to multiple appliances, or
 * make an aggregate tap from several small taps

Usually, people buy network packet brokers for these purposes.
Since regular switches move packets based on their L2 headers,
*plugging a tap into a regular switch is asking for trouble!*
Packet brokers solve the problem by using configuration rules,
often very simply copying packets from one NIC to other NIC's.

There is another way, too, instead of buying a packet broker.
A regular Linux host, running fluxcap, can take in a tap and
re-transmit it. Or, it can take in several taps and aggregate.
It can add or remove VLAN tags on the packets while doing so.
It can encapsulate a tap into a GRE tunnel over an IP network.
It is a command-line tool, allowing the user to receive, merge
and re-transmit network taps using the NIC's of the Linux host.

Fluxcap is written in C, MIT licensed, and for Linux only. It
runs on Ubuntu, RHEL, CentOS and others. No special hardware
is needed.

# Build & install

## Prereqs

In order to build and use fluxcap you need to install a few packages.

    # Ubuntu
    sudo apt-get install git gcc automake autoconf libtool \
      libncurses5-dev ethtool

    # RHEL/CentOS
    sudo yum install git gcc automake autoconf libtool \
      ncurses-devel ethtool

Last, libshr must be built and installed prior to building fluxcap.
Originally made for fluxcap, it is now built as a separate library.

    git clone https://github.com/troydhanson/shr.git
    cd shr
    autoreconf -ivf
    ./configure
    make
    sudo make install
    sudo ldconfig

The libshr libraries and header files are now in `/usr/local/lib`
and `/usr/local/include`.

## fluxcap

In the top-level directory of fluxcap, run:

    git submodule update --init --recursive
    ./autogen.sh
    ./configure
    make
    sudo make install

This installs `fluxcap`, typically into `/usr/local/bin`.

# Preparing the host

These things need to be done *at each system boot*.

 * disable hardware offloading on the receive/transmit NIC's
 * set up iptables to prevent accidental traffic on NIC's
 * make sure NIC's are up and not assigned IP addresses
 * mount a ramdisk for fluxcap's ring buffers

This script can be used. Save the script somewhere, make it executable,
and execute it at startup via `/etc/rc.local` or similar.

    #!/bin/bash
    INTERFACES="ens33 enp4s0" # replace with YOUR NIC names!
    for IF in $INTERFACES
    do
      ethtool -K $IF tso off  # TCP segmentation offload (output)
      ethtool -K $IF ufo off  # UDP segmentation offload (output)
      ethtool -K $IF gso off  # generic segmentation offload (output)
      ethtool -K $IF gro off  # generic receive offload (input)
      ethtool -K $IF lro off  # large receive offload (input)

      /sbin/iptables -A INPUT  -i $IF -j DROP
      /sbin/iptables -A OUTPUT -o $IF -j DROP

      /sbin/ip link set dev $IF up
    done

Last we mount a ramdisk at each boot. You can name it anything but
this document uses /ram as the mountpoint. Add to /etc/fstab:

    none  /ram   ramfs auto,noatime 0 0

Then make the mountpoint and mount it:

    mkdir /ram
    mount /ram

### why disable offloads?

When hardware offloading is left on, the NIC presents artificially large
packets to the Linux host, by merging together IP packets in valid ways
to reduce work the kernel would have to do in software. However, this is 
really _undesirable_ for tap replication (and any kind of packet analysis)
because the larger, conglomerated packets fail re-transmission; they may
vastly exceed MTU. Analysis tools want the original packets in any case.
For the curious, an explanation of some offload parameters can be found
[here](https://red.ht/2e608Oo). The usual symptom of skipping this step
is to see fluxcap emit errors like `sendto: message too long`.

### why use iptables?

It is just an added layer of protection from the host generating traffic
of its own on the NIC. It is optional.

### why use ramfs?

While tmpfs is newer, it can swap, and that is undesirable for this program.
Use of ramfs is considered safe because we only create a few fixed-sized
memory buffers in it.

# Configuring fluxcap

Here, we show how to run fluxcap by hand to set up tap replication or
aggregation. In order to persist, these commands have to run at each
system boot. We can use a process supervisor for that, but we show it
by hand first. Everything needs to be run as root.

## Tap replication

Suppose we have three available NIC's on a host and we want to replicate
a tap coming into eth1, re-transmit it on eth2 and eth3. We'll assume
that eth0 is a management NIC and, obviously, we leave that one alone.

    eth0: management (leave alone)
    eth1: tap from Cisco switch
    eth2: tap output (copy #1)
    eth3: tap output (copy #2)

Remember the ramfs we mounted earlier? We mounted it at /ram. That is
where we will create a fluxcap ring buffer. In this setup we have one
input NIC, so we only need one ring buffer.

    cd /ram
    fluxcap -cr -s 100m cisco

Now if you run `ls /ram/cisco` you see a 100 mb file there. It's a 
memory buffer. It's a file too. Everything in unix is a file, right?
The name "cisco" could be anything, but when you start working with
a dozen taps coming into one host, it helps to name things clearly.

Why did we choose 100 mb size? (This uses real RAM by the way, so
beware of making it too large; consider what RAM your host has free).
The idea is we want the ring to be "large enough" that it can buffer
data from the incoming tap long enough to get read by the transmit
processes that will send out the output NIC's. Here "long enough" 
means "before the data in the ring buffer gets written over". One
could contemplate how to size the buffer - but we will just pick
a number. You can use 1G (that is, a gigabyte) for the buffer if
you have a lot of RAM, and just forget about it. A gigabyte can 
buffer about ten seconds of traffic from a fully loaded gigabit NIC.
In any case, we can eyeball the I/O rates, and watch for drops- but
first we have to start up the receive and transmit processes.

    cd /ram
    fluxcap -rx -i eth1 cisco &
    fluxcap -tx -i eth2 cisco &
    fluxcap -tx -i eth3 cisco &

At this point it is up and running. The first process captures on 
eth1 into the ring /ram/cisco. The second process transmits on eth2,
and the last on eth3. (If you see messages like "sendto: too long" 
you should review the section on disabling NIC offloads above).

We used `&` to put them in the background. You could run them in
three separate terminals instead. In real life we put them under
a process supervisor but that's for later.

We can watch the I/O rates this way. (Hint: it looks better if you
run inside a tmux session).

    fluxcap -io cisco

You can run `fluxcap -h` to see further options. For example we
could add a VLAN tag on the data when it comes in from eth1. That
helps keep things straight if we merge several taps down the road.

## Tap aggregation

Suppose we have two input taps. We want to aggregate them. We want
to transmit the aggregate tap on a third interface.

    enp0: management (leave alone)
    enp1: tap from Cisco switch
    enp2: tap from Dell switch
    enp3: aggregate (Cisco+Dell) output

We want to create a ring buffer for each input NIC, so we need two.
Doing this by hand at the shell prompt, we'd run:

    cd /ram
    fluxcap -cr -s 100m cisco dell

Last we run two receive processes and two transmit processes:

    fluxcap -rx -i enp1 cisco &
    fluxcap -rx -i enp2 dell &
    fluxcap -tx -i enp3 cisco &
    fluxcap -tx -i enp3 dell &

We can run `fluxcap -io cisco dell` at this point to see the I/O rates.
In an aggregation scenario it may be helpful to synthesize VLAN tags on
the input taps so they can still be distinguished after aggregation. We
could have used `-V 100` on the cisco receiver, and `-V 200` for dell,
for example.

## Under a process supervisor

Running things by hand is good for testing. If persistence is needed, and
resilience in the face of things like NIC's going up and down when someone
unplugs the cable and plugs it back in, then use a process supervisor. An
example using [pmtr](http://github.com/troydhanson/pmtr) is shown here.

    # pmtr.conf

    job {
      dir /ram
      cmd /usr/local/bin/fluxcap -cr -s 100m cisco dell
      wait
      once
    }

    job {
      dir /ram
      cmd /usr/local/bin/fluxcap -rx -i enp1 cisco
    }

    ...

This way, pmtr starts things at boot, and restarts proceses that exit.
The NIC offload script could be run from here too, instead of rc.local.

## Encapsulation modes

Fluxcap can transmit taps over a regular network, using a GRE tunnel.
To elaborate, this means receiving a tap on one NIC, then transmitting
the tap packets _inside a layer of encapsulation_ over an IP network.

The supported tunnel encapsulation modes are GRETAP, GRE and ERSPAN.
GRETAP, aka TEB for "transparent ethernet bridging", is preferred. It
preserves the MAC addresses in the encapsulation, whereas GRE does not.
In this example, the recipient tunnel endpoint is 192.168.102.100:

    fluxcap -tx -E gretap:192.168.102.100 ring

Below we see it's easy to reverse the encapsulation on the receiving end.

#### Decapsulation 

If the recipient host is Linux, it can decapsulate the tunnel for us.
This creates a synthetic NIC on the host, ready for use with a packet
analysis tool, which looks like the remote tap cable is plugged in.

Confirm the recipient is getting the tunneled packets first.

    tcpdump -n "proto gre"

Then, to have Linux decapsulate for us, modify these commands by
replacing 192.168.102.100 with the recipient IP address, and replacing
192.168.102.1 with the transmitter's IP address.

    # gretap

    modprobe ip_gre
    ip link add gretap1 type gretap local 192.168.102.100 remote 192.168.102.1
    ip link set gretap1 up

Now we can use gretap1 as if it were plugged into the remote tap. Try running
`tcpdump -i gretap1 -nne` for example.  If we had used gre instead of gretap:

    # gre

    modprobe ip_gre
    ip tunnel add gre1 mode gre remote 192.168.102.1 local 192.168.102.100 ttl 255
    ip link set gre1 up

##### firewalld

You may need to ensure that iptables/firewalld allow the traffic. On a CentOS 7
system, `sudo systemctl stop firewalld` permits the data to arrive on gretap1.

##### MTU consideration

When encapsulating packets, they grow. If the original packet was at the MTU of
its network, and GRETAP encapsulation adds 24 bytes, then each packet may become
two packets when sent over the tunnel. This occurs via IP fragmentation and is
reversed on the remote end invisibly.

However, fragmentation can be eliminated by either raising the MTU on the tunnel
network, if that is an option, or by truncating the packets (`-s`) to a max
length when encapsulating.  On a network with a 1500 byte MTU, `-s 1476` leaves
room for the GRETAP header and stays within MTU.

    fluxcap -tx -s 1476 -E gretap:192.168.102.100 ring

## Other features

Run `fluxcap -h` to see other options.


