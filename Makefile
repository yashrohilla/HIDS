#
#
# Makefile
#
# HIDS pac_cap
#

pac_cap: Makefile pac_cap.c
					gcc -o pac_cap pac_cap.c -lpcap -lcs50
arp_sniffer: Makefile arp_sniffer.c
					gcc -o arp_sniffer arp_sniffer.c -lpcap


