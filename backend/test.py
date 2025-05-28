from scapy.all import sniff


def handle(pkt):
    print(pkt)


sniff(
    iface=r"Wi-Fi",
    prn=handle,
    store=False,
    promisc=True,
)
