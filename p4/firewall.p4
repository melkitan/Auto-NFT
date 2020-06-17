table firewall_with_tcp {
    key = {
        hdr.ipv4.srcAddr : ternary;
        hdr.ipv4.dstAddr : ternary;
        hdr.tcp.srcPort  : ternary;
        hdr.tcp.dstPort  : ternary;
    }
    actions = {
        drop;
        noAction;
    }
}

table firewall_with_udp {
    key = {
        hdr.ipv4.srcAddr : ternary;
        hdr.ipv4.dstAddr : ternary;
        hdr.udp.srcPort  : ternary;
        hdr.udp.dstPort  : ternary;
    }
    actions = {
        drop;
        noAction;
    }
}

table forward_table {
    key = {
    }
    actions = {
        do_forward;
    }
}

control ingress {
    apply(forward_table);
    if (valid(hdr.udp)) {
        apply(firewall_with_udp);
    }
    else if (valid(hdr.tcp)) {
        apply(firewall_with_tcp);
    }
}