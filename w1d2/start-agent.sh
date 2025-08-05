#!/bin/bash

# Start the packet filter in the background
# (the environment variable CONTAINER is set here just for the convenience of the bootcamp team to make testing easier)
CONTAINER=nfqueue python w1d2_answers_nfqueue.py > /tmp/nfqueue.log 2>&1 &

# Allow all traffic from root user - we run mitmproxy as root to forward connections in case of non-evil requests
sudo iptables -A OUTPUT -p tcp -m owner --uid-owner 0 -j ACCEPT
# Allow traffic to localhost on port 8080 (where the agent will run)
sudo iptables -A OUTPUT -p tcp -d localhost --dport 8080 -j ACCEPT
# Everything else will be sent to the NFQUEUE
sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 0

# UNCOMMENT THE LINES BELOW FOR EXERCISE 9.2
# # Allow all traffic from root user (UID 0)
# sudo iptables -A OUTPUT -p udp -m owner --uid-owner 0 -j ACCEPT
# # Allow UDP to localhost:53 (for DNS to your mitmproxy)
# sudo iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
# # Allow established connections (for responses)
# sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# # Drop all other UDP traffic
# sudo iptables -A OUTPUT -p udp -j DROP

# Run the agent
echo "Running agent..."
python w1d2_answers_agent.py
