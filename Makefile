#
#
# Makefile
#
# HIDS pac_cap
#

pac_cap: Makefile pac_cap.c
					gcc -o pac_cap pac_cap.c -lpcap


