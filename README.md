# VLAN
## Goal
In this project, student will learn what Network Virtualization is, how to achieve Network Virtualization and practice how to use SDN and Mininet.
## My design and explanation of how my design work
Using VLAN tagging/trunking can help us send packets to the host under same tenant correctly. When an “untagged” broadcast packet is received, then it must be flood to all access ports and trunk ports which are members of the same VLAN. Before sending to trunk port, it must be tagged with appropriate VLAN ID. Similarly, when a “tagged” broadcast packet is received, before flooding to an access port, the tag must be popped.
I will use port-based classification to configure VLAN on a per port basis. To complete this project, we also need functions below: OFPActionPushVlan(), OFPActionPopVlan(), OFPMatch() and OFPActionSetField().
