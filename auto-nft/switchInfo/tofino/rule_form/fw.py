from ipaddress import ip_address

def insert_rule(bfrt):
    p4 = bfrt.hypervisor_tf_sw
    # fw
    p4.Ingress.table_config_at_initial.add_with_set_initial_config(3, 3, 3, 0xb101, 0xb0110)
    p4.Ingress.table_header_match_160_stage3.add_with_set_action_id(3, 0x0000000000000000000000000A0A000000000000, 0x000000000000000000000000FFFFFF0000000000, 0x00000001)
    p4.Ingress.table_header_match_160_stage3.add_with_set_action_id(3, 0x0000000000000000000000000A0A020000000000, 0x000000000000000000000000FFFFFF0000000000, 0x80000000)
    p4.Ingress.table_header_match_161_stage3.add_with_set_action_id(3, 0x0000005000000000000000000000000000000000, 0x0000FFFF00000000000000000000000000000000, 0x00000001)
    p4.Ingress.table_header_match_161_stage3.add_with_set_action_ids(3, 0x0000001600000000000000000000000000000000,0x0000FFFF00000000000000000000000000000000, 0x80000000)
    p4.Ingress.table_action_forward_stage3.add_with_action_forward(3, 163)
    p4.Ingress.table_action_mod_112_dstAddr_stage3.add_with_action_mod_112_dstAddr(3, 0x00000000030000000000000000)
    p4.Ingress.table_action_drop_stage1.add_with_action_drop(3)
    p4.Ingress.table_action_drop_stage2.add_with_action_drop(3)
    p4.Ingress.table_action_drop_stage3.add_with_action_drop(3)

    # l2fwd
    p4.Ingress.table_config_at_initial.add_with_set_initial_config(1, 1, 1, 0xb100, 0xb0001)
    p4.Ingress.table_header_match_112_stage1.add_with_set_action_id(1, 0x0000000000020000000000000000, 0xFFFFFFFFFFFF0000000000000000, 0x00000001)
    p4.Ingress.table_action_forward_stage1.add_with_action_forward(1, 160)

    # l3fwd
    p4.Ingress.table_config_at_initial.add_with_set_initial_config(2, 2, 2, 0xb100, 0xb0010)
    p4.Ingress.table_header_match_160_stage2.add_with_set_action_id(2, 0x000000000000000000000000000000000A0A0200, 0x00000000000000000000000000000000FFFFFF00, 0x00000111)
    p4.Ingress.table_action_forward_stage2.add_with_action_forward(2, 162)
    p4.Ingress.table_action_mod_112_dstAddr_stage1.add_with_action_mod_112_dstAddr(2, 0x00000000010000000000000000)
    p4.Ingress.table_action_mod_112_dstAddr_stage2.add_with_action_mod_112_dstAddr(2, 0x00000000020000000000000000)
    p4.Ingress.table_action_mod_112_srcAddr_stage1.add_with_action_mod_112_srcAddr(2, 0x0000000000000000000000010000)
    p4.Ingress.table_action_mod_112_srcAddr_stage2.add_with_action_mod_112_srcAddr(2, 0x0000000000000000000000010000)
    p4.Ingress.table_action_mod_112_srcAddr_stage3.add_with_action_mod_112_srcAddr(2, 0x0000000000000000000000010000)

    # lb
    p4.Ingress.table_config_at_initial.add_with_set_initial_config(4, 4, 1, 0xb100, 0xb0001)
    p4.Ingress.table_header_match_112_stage1.add_with_set_action_id(4, 0x0000000000020000000000000000, 0x0000000000000000000000000000, 0x00078001)
    p4.Ingress.table_action_hash_stage1.add_with_action_hash(4)
    p4.Ingress.table_action_extract_meta_160_stage1.add_with_action_extract_meta_160(4, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    p4.Ingress.table_action_extract_meta_161_stage1.add_with_action_extract_meta_160(4, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    p4.Ingress.table_action_temporal_lb_forward_stage1.add_with_action_forward(0x00000001, 0x00000001, 164)

    bfrt.complete_operations()