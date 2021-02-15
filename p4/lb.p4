table load_balance {
    key = {
        hdr.ipv4.dstAddr : ternary;
    }
    actions = {
        hash;
    }
}

table forward {
    key = {
        hash_value : exact;
    }
    actions = {
        do_forward;
    }
}

control ingress{
    apply(load_balance);
    apply(forward);
}