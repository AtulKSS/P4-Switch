# P4 Switch – Programmable Networking and Security Experiments

This repository contains the work completed during a hands-on study of **P4 programmable networking** using **BMv2, Mininet, and P4Runtime**. The project focuses on packet processing, forwarding, filtering, and basic network security policies implemented using P4 programmable switches.

## Technologies Used

- **P4** – Programmable data-plane language
- **BMv2** – Behavioral Model software switch
- **Mininet** – Virtual network emulator
- **P4Runtime** – Runtime interface for controlling P4 switches
- **Python** – Controller and network automation
- **Ubuntu/Linux** – Development and testing environment

## Work Completed

### 1. Basic P4 Packet Processing

A basic P4 program was developed and tested to understand packet parsing and processing.

The parser was implemented to:

- Extract the Ethernet header
- Identify IPv4 packets using Ethernet EtherType
- Extract the IPv4 header
- Process packets using P4 tables and actions

### 2. IPv4 Forwarding

P4 tables and actions were used to implement basic packet forwarding.

```text
Incoming Packet
       |
       v
Ethernet Parser
       |
       v
IPv4 Parser
       |
       v
P4 Table Lookup
       |
       v
Forwarding Action
       |
       v
Output Port
```

The forwarding functionality was tested using a Mininet topology with BMv2 P4 software switches.

### 3. Host Blocking

Network security actions were created to block traffic from selected hosts.

The switch can apply a drop action when traffic matches a configured source or destination host.

```text
Host Traffic
     |
     v
Match Rule
     |
     +---- Match ----> DROP
     |
     +---- No Match -> FORWARD
```

This demonstrates how access-control policies can be implemented directly in the P4 data plane.

### 4. TCP Packet Blocking

Packet filtering was implemented based on the IP protocol field.

TCP traffic can be identified and dropped using a P4 table and action.

```text
Packet
   |
   v
IPv4 Header
   |
   +---- TCP ------> DROP
   |
   +---- Other ----> FORWARD
```

This demonstrates protocol-specific packet filtering directly inside the programmable switch.

### 5. P4 Firewall Experiments

Basic firewall-style functionality was explored using P4 tables and actions.

The experiments included:

- Blocking traffic from selected hosts
- Blocking communication involving selected hosts
- Blocking TCP traffic
- Allowing other traffic to pass through
- Testing packet filtering rules using Mininet

Python scripts were also used for configuring and testing the P4 switch behavior.

## Network Topology

The experiments were performed using virtual hosts and P4 switches in Mininet.

A simple topology is shown below:

```text
       +--------+
       |   h1   |
       +----+---+
            |
            |
       +----+----+
       |    s1   |
       | P4/BMv2 |
       +----+----+
            |
            |
       +----+---+
       |   h2   |
       +--------+
```

Multi-host and multi-switch topologies were also used during the experiments.

## Testing

The implementations were tested using Mininet networking tools and packet transmission tests.

The experiments verified:

- Packet forwarding
- Output-port selection
- Host-to-host communication
- Packet filtering
- TCP blocking
- Packet dropping
- P4 table-based security rules

Successful packet transmission between hosts was achieved through the P4 switch after configuring the required forwarding rules.

## Repository Structure

```text
P4-Switch/
│
├── exercises/
│   └── basic/
│       ├── basic.p4
│       ├── firewall_controller.py
│       └── ids.py
│
├── Screenshots/
│   └── ...
│
├── src/
│   └── ...
│
└── tutorials_backup/
    └── ...
```

## P4 Concepts Practiced

The project provided practical experience with:

- P4 headers
- Parsers
- Parser states
- Header extraction
- IPv4 processing
- P4 actions
- P4 tables
- Match-action processing
- Packet forwarding
- Packet dropping
- Protocol-based filtering
- Runtime table configuration
- P4Runtime
- BMv2
- Mininet

## Project Objective

The main objective of this work was to gain practical experience with **programmable data planes** and understand how networking functions such as forwarding, filtering, and firewall rules can be implemented directly inside a P4 switch.

The experiments also provide a foundation for further research in **network security, intrusion detection, and DDoS detection and mitigation using P4 programmable switches and machine learning**.

## Future Work

Possible extensions include:

- Collecting live network traffic and flow statistics
- Implementing advanced firewall policies
- Detecting abnormal traffic patterns
- Integrating machine-learning-based traffic classification
- Implementing low-rate DDoS detection
- Developing P4-based mitigation mechanisms
- Evaluating detection and mitigation performance using Mininet

## Acknowledgment

This project was developed as part of hands-on experimentation with **P4 programmable networking**, using the P4 ecosystem, BMv2, Mininet, and P4Runtime.
