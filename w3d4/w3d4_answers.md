Container GPU Issues: What security vulnerabilities might arise when GPUs are shared between containers or when containers have direct GPU access?
VM GPU Passthrough: What attack vectors are introduced when GPUs are passed through directly to virtual machines?
Isolation Concerns: How might GPU memory persistence, side-channel attacks, or privilege escalation differ between containerized and VM environments?

Write down two specific security risks for each deployment model (containers vs. VMs) and suggest a mitigation strategy for each risk.
Containers (Stuff I didn't know)
1. GPU memory isn't automatically cleared between container executions
2. Containers typically share the host kernel and GPU drivers.
VMs
1. GPU passthrough typically grants VMs direct memory access (DMA) capabilities
2. When GPUs are passed through to VMs, malicious guests can potentially flash compromised firmware to the GPU's EEPROM/NVRAM. This persistent firmware modification survives VM destruction and host reboots, potentially compromising future VMs that use the same GPU.
