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
}