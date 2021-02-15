table route {
    key = {
        hdr.ipv4.dstAddr : exact;
    }
    actions = {
        mod_112_srcaddr;
    }
}

table dmac {
    key = {
        hdr.eth.dstAddr : exact;
    }
    actions = {
        do_forward;
    }
}

control ingress{
    apply(dmac);
    apply(route);
}