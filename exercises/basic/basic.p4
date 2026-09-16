// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;


/*************************************************************************
*********************** H E A D E R S  ***********************************
* This program skeleton defines minimal Ethernet and IPv4 headers and    *
* a simple LPM (Longest-Prefix Match) IPv4 forwarding pipeline.          *
* The exercise intentionally leaves TODOs for learners to implement.     *
*************************************************************************/

typedef bit<9>  egressSpec_t;   // Standard BMv2 uses 9 bits for egress_spec
typedef bit<48> macAddr_t;      // Ethernet MAC address
typedef bit<32> ip4Addr_t;      // IPv4 address

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* Added TCP header */

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* Addedd UDP header */

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


struct metadata {
    bit<1> blocked;
}

/* Store TCP and UDP headers */

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

/*************************************************************************
*********************** P A R S E R  *************************************
* New to P4? A typical parser does this:
*   start -> parse_ethernet
*   parse_ethernet:
*       if etherType == TYPE_IPV4 -> parse_ipv4
*       else accept
*   parse_ipv4 -> accept
* This skeleton leaves the actual states as a TODO to implement later.   *
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
	packet.extract(hdr.ethernet);
	
	transition select(hdr.ethernet.etherType) {
		TYPE_IPV4: parse_ipv4;
		default:accept;
	}
}

	/* Modifued parse_ipv4 to add tcp and udp */

    state parse_ipv4 {
   	packet.extract(hdr.ipv4);

    	transition select(hdr.ipv4.protocol) {
        IP_PROTO_TCP: parse_tcp;
        IP_PROTO_UDP: parse_udp;
        default: accept;
    }
}	

state parse_tcp {
    packet.extract(hdr.tcp);
    transition accept;
}

state parse_udp {
    packet.extract(hdr.udp);
    transition accept;
}


}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
* High-level intent:
*   - Do an LPM lookup on IPv4 dstAddr
*   - On hit, call ipv4_forward(next-hop MAC, output port)
*   - Otherwise, drop or NoAction (as configured)                         *
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /*********************************************************************
     * NOTE FOR NEW READERS:
     * 'ipv4_forward(dstAddr, port)' is invoked by table 'ipv4_lpm'.
     *
     * The values for 'dstAddr' and 'port' are *action data* supplied by
     * the control plane when it installs entries in 'ipv4_lpm'.
     *
     * They mean:
     *   - dstAddr  => Ethernet destination MAC for the next hop
     *   - port     => output port (ultimately written to standard_metadata.egress_spec)
     *
     * Example (BMv2 simple_switch_CLI):
     *   table_add ipv4_lpm ipv4_forward 10.0.1.1/32 => 00:00:00:00:01:00 1
     * which passes MAC=00:00:00:00:01:00 and PORT=1 as action parameters
     * into ipv4_forward(dstAddr, port).
     *********************************************************************/
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
	standard_metadata.egress_spec = port;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /*********************************************************************
     * LPM table for IPv4:
     *   - Matches on hdr.ipv4.dstAddr using longest-prefix match (lpm)
     *   - On hit, calls ipv4_forward with *action data* populated by the
     *     control plane when it installs the table entry.
     *********************************************************************/
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

/* Added action blockpacket table */
action block_packet() {
    meta.blocked = 1;
    mark_to_drop(standard_metadata);
}

table tcp_port_block {
    key = {
        hdr.tcp.dstPort : exact;
    }

    actions = {
        block_packet;
        NoAction;
    }

    size = 32;

    default_action = NoAction();
}

/* Commented apply block 
apply {
    if (hdr.ipv4.isValid()) {

        /*********************************************************************/
        /* Commented out the rule that blocks h1 ping h3 */

        /*

        // Block h1 to h3
        if (hdr.ipv4.srcAddr == 0x0A000101 &&
            hdr.ipv4.dstAddr == 0x0A000303) {

            mark_to_drop(standard_metadata);

        } else {

            ipv4_lpm.apply();
        }

        */
        /*********************************************************************/

        /* Block TCP traffic destined for port 5001 (iperf) */
        //if (hdr.tcp.isValid() &&
         //   hdr.tcp.dstPort == 5001) {

           // mark_to_drop(standard_metadata);

       // } else {

            /* Normal IPv4 forwarding */
      //      ipv4_lpm.apply();
    //    }
  //  }
//}
//}


/* new apply block */

apply {
    if (hdr.ipv4.isValid()) {

        meta.blocked = 0;

        if (hdr.tcp.isValid()) {
            tcp_port_block.apply();
        }

        if (meta.blocked == 0) {
            ipv4_lpm.apply();
        }
    }
}
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
* Often used for queue marks, mirroring, or post-routing edits.          *
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
* This block shows how to compute IPv4 header checksum when needed.      *
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
* The deparser serializes headers back onto the packet in order.         *
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
