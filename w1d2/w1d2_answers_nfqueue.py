
try:
    from scapy.all import IP

    import importlib

    # Don't use `import netfilterqueue` directly because that would get to the _test file, which would then fail when imported in the mitmproxy container.
    netfilterqueue = importlib.import_module("netfilterqueue")
    NetfilterQueue = getattr(netfilterqueue, "NetfilterQueue")
except ImportError:
    print("nfqueue and/or scapy not installed. Ignoring this error for scuffed reasons.")

    class NetfilterQueue:
        def bind(self, *args, **kwargs):
            print("Warning: NetfilterQueue not available. This is a scuffed solution.")

        def run(self):
            print("Warning: NetfilterQueue run method not available. This is a scuffed solution.")

        def unbind(self):
            print("Warning: NetfilterQueue unbind method not available. This is a scuffed solution.")


# IP to block
BLOCKED_IPS = ["49.12.34.32", "85.188.1.133"]


def process_packet(packet):
    """
    Process packets from NFQUEUE and decide whether to accept or drop them.

    This function is called for each packet that matches our iptables rule.
    You need to:
    1. Parse the packet payload using Scapy
    2. Check if it's destined for a blocked IP
    3. Drop blocked packets, accept others

    Args:
        packet: NetfilterQueue packet object
    """
    try:
        # Parse packet
        pkt = IP(packet.get_payload())

        # Check if destination is blocked IP
        if pkt.dst in BLOCKED_IPS:
            print(f"Dropping packet to IP {pkt.dst}")
            packet.drop()
        else:
            # Allow all other packets
            packet.accept()

    except Exception as e:
        print(f"Error processing packet: {e}")
        # On error, drop packet to be safe
        packet.drop()


from w1d2_test import test_packet_processor

test_packet_processor(process_packet)
print("Starting packet filter...")
nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping packet filter...")
finally:
    nfqueue.unbind()
