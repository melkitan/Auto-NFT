table dmac {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {forward;}
    size : 512;
}

control ingress{
    apply(dmac);
}