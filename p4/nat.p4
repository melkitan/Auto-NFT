table nat {
    key = {
        hdr.ipv4.srcAddr : ternary;
        hdr.ipv4.dstAddr : ternary;
    }
    actions = {
        nat_input;
        nat_output;
    }
}

table forward {
    key = {
        hdr.ipv4.dstAddr : exact;
    }
    actions {
        do_forward;
        drop;
    }
}

table send_frame {
    key = {
        standard_metadata.egress_port: exact;
    }
    actions {
        set_smac;
        drop;
    }
    size: 256;
}

control ingress {
    if (valid(hdr.ipv4)) {
        apply(nat)
        apply(forward);
        apply(send_frame);   
    }
}