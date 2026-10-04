# --> The vpn module is built by several work streams at once, each in its own subdirectory:
#   include/sbox/vpn/wg/,    src/wg/,    tests/wg/     WireGuard (kernel or user space) and the overlay driver
#   include/sbox/vpn/ipsec/, src/ipsec/, tests/ipsec/  XFRM, IKEv2 responder
#   include/sbox/vpn/l2tp/,  src/l2tp/,  tests/l2tp/   IKEv1 (for L2TP/IPsec), L2TP, PPP
# Sources and tests are globbed recursively, so no stream needs to edit this file.
sbox_add_module(vpn DEPENDS net LINK certpp::certpp)
