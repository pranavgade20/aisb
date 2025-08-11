# %%
"""
# W2D1 - Securing Model Weights: The RAND Framework

Today you'll explore what it would take to protect frontier model weights. For this we need to understand the threats, adversaries, and available security measures specific for labs working on such models.

We'll study the topics above based on RAND's comprehensive report "[Securing AI Model Weights](https://www.rand.org/pubs/research_reports/RRA2849-1.html)" which provides a structured approach to this problem.

<!-- toc -->

<!-- ## Content & Learning Objectives -->

<!-- FIXME: update -->


## Introduction: The RAND Framework

In 2024, RAND Corporation published a comprehensive framework for securing AI model weights. To date, it is the most comprehensive compilation of attack vectors and recommended security measures specific to protecting frontier models. The key contributions include:

1. **38 distinct attack vectors categorized into 9 groups**, from conventional cyber attacks to AI-specific vulnerabilities like model extraction and distillation
2. **Capability assessment matrix** that estimates the feasibility of each attack vector for different threat actors (e.g., revealing that ~12 vectors are feasible only for state actors)
3. **Five security levels** with concrete benchmarks that map defensive measures to specific threat categories, helping organizations avoid both security gaps and wasteful over-engineering
4. **Evidence-based analysis** drawing from hundreds of real-world examples, demonstrating that these attacks aren't theoretical but have been successfully executed
5. **Actionable recommendations** that acknowledge the trade-offs between security and operational efficiency, with specific guidance for different deployment scenarios (training, research, API access, on-premises)

This framework is particularly valuable because it bridges the gap between the AI and security communities, providing a shared vocabulary for discussing threats that range from opportunistic criminals to nation-state actors conducting operations with budgets exceeding $1 billion.

### Why this matters
One of the key reasons for being familiar with the RAND framework is that it **grounds considerations** for securing AI model weights in evidence-based analysis rather than staying with abstract arguments, and it bridges the gap between the AI and security communities.

### The core recommendations
The report highlights these recommendationas as urgent priorities for AI organizations because they are critical for weights security, feasible, but not comprehensively implemented (as of day of writing) in frontier AI organizations:

- Develop a security plan for a comprehensive threat model focused on preventing unauthorized access and theft of the model's weights.
- Centralize all copies of weights to a limited number of access-controlled and monitored systems.
- Reduce the number of people authorized to access the weights.
- Harden interfaces for model access against weight exfiltration.
- Implement insider threat programs.
- Invest in defense-in-depth (multiple layers of security controls that provide redundancy in case some controls fail).
- Engage advanced third-party red-teaming that reasonably simulates relevant threat actors.
- Incorporate confidential computing to secure the weights during use and reduce the attack surface.

However, even these would not be sufficient against the most capable actors. Further recommendations therefore include:

- physical bandwidth limitations between devices or networks containing weights and the outside world
- development of hardware to secure model weights while providing an interface for inference, analogous
to hardware security modules in the cryptographic domain
- setting up secure, completely isolated networks for training, research, and other more advanced interactions with weights.

### Vocabulary

<details>
<summary>Quick Vocabulary Reference</summary>

- **Attack Vectors**: Specific methods attackers use to breach security (e.g., zero-day exploits, social engineering)
- **Operational Capacity (OC)**: A measure of an attacker's resources, skills, and capabilities
- **Security Levels (SL)**: Defensive postures designed to protect against specific OC levels
- **APT (Advanced Persistent Threat)**: Sophisticated, often state-sponsored attackers who maintain long-term presence
- **Zero-day**: A vulnerability unknown to vendors with no available patch
- **Supply Chain Attack**: Compromising a target through their vendors or dependencies
- **Insider Threat**: Attacks from individuals with legitimate access (employees, contractors)
- **Defense-in-Depth**: Multiple independent security layers to prevent single points of failure
- **Kill Chain**: The sequence of steps an attacker takes from initial reconnaissance to achieving objectives
- **Exfiltration**: The unauthorized transfer of data (or model weights) out of a system

</details>

## 1️⃣ Operational Capacity Categories
In this section, you'll familiarize yourself with the first two key contributions attack capability categories, and relevant attack vectors.

### Exercise 1.1: Operational Capacity Categories
<!-- FIXME: add difficulty / importance -->

Start by **[downloading the report](https://www.rand.org/pubs/research_reports/RRA2849-1.html)** and **read chapter 4**.

**Quiz:**

<details>
<summary>What is the approximate budget range for an OC3 (Cybercrime Syndicates) operation?</summary>
Up to $1 million
</details>

<details>
<summary>Which OC level first includes insider threats as a key actor type?</summary>
OC3 (alongside cybercrime syndicates; despite being quite different in nature, the level of investment required to robustly defend against them is comparable)
</details>

<details>
<summary>How many operations per year can top cyber-capable nations execute at the OC4 level?</summary>
More than 100 times per year
</details>

<details>
<summary>What's the main difference between OC4 and OC5 operations?</summary>
OC5 represents the handful of top-priority operations with budgets up to $1B and capabilities years ahead of public knowledge, while OC4 are standard/routine state operations with ~$10M budgets
</details>

<details>
<summary>If an attacker has zero-days but only $1,000 budget and works alone, which OC level?</summary>
Still OC1 - the categories are based on overall capacity, not single capabilities
</details>

Also recall the [LastPass breach from 2022](https://www.arxiv.org/pdf/2502.04287) we looked into during the threat modeling day. What level of operational capacity (OC) do you think the attackers had?

### Exercise 1.2: Attack vectors bingo
Open [resources/bingo.html](./resources/) (in VS Code: right-click the file, select Reveal in Finder/File Explorer, and double-click it there).

It shows the attack vectors from the RAND report. Can you find at least 9 that we already covered last week?

### Exercise 1.3: Mapping Attack Vectors to Operational Capacity Levels

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪

Different attack vectors require vastly different resources, expertise, and infrastructure to execute successfully. Understanding which threats are realistic from which actors helps organizations prioritize their defenses efficiently.

**Your Task**: For each attack vector below, guess the *minimum* Operational Capacity level that could execute it with high likelihood (score of 4-5 out of 5 in the RAND framework; see Box 5.1 in the report for the exact meaning of the scores). **You'll then compare your guesses against the report findings.**

Consider not just technical feasibility but also:
- Required infrastructure and tools
- Time and persistence needed
- Risk tolerance (some attacks risk detection/attribution)
- Access to specialized knowledge or capabilities


| Attack Vector | Minimum OC Level |
|--------------|------------------|
| Password brute-forcing and cracking | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Supply chain compromise (hardware/software) | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Exploiting unpatched vulnerabilities | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Side-channel attacks (TEMPEST) | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Military takeover of facilities | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Finding and exploiting individual zero-days | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Physical access to data centers | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Bribes and cooperation (human intelligence) | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Social engineering for credentials | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Intentional ML-specific backdoors | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Direct access to zero-days at scale | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |
| Model extraction through API | <select><option>Please select</option><option>OC1 (Amateur) and above</option><option>OC2 (Professional) and above</option><option>OC3 (Cybercrime/insiders) and above</option><option>OC4 (Standard state ops) and above</option><option>OC5 (Top-priority state)</option><option>None</option></select> |

Then compare your answers with the key below.

<details>
<summary><b>Solution and Explanations</b></summary>

| Attack Vector | Minimum OC Level | Explanation |
|--------------|------------------|-------------|
| Password brute-forcing and cracking | OC5 | Even at OC5, only reaches score of 4. Modern password defenses (salting, slow hashing, MFA) make this attack increasingly difficult. Success requires massive computational resources or targeting weak implementations. |
| Services and equipment the organization uses (Supply chain) | OC3 | Cybercrime groups have successfully executed supply chain attacks (e.g., Kaseya ransomware). Requires months of planning, understanding of vendor relationships, and sophisticated malware development capabilities. |
| Exploiting vulnerabilities for which a patch exists | OC2 | Professional hackers can reliably exploit known vulnerabilities. Many organizations lag in patching, and professionals have the persistence to find vulnerable targets through scanning. |
| Side-channel attacks (including through leaked emanations; i.e., TEMPEST attacks) | None | Never reaches score ≥4. TEMPEST attacks require specialized equipment, physical proximity, and expertise that even top state actors struggle to deploy reliably. |
| Military takeover | None | Never reaches score ≥4. Even for nation-states (OC5 score=2), military operations are extremely rare, risky, and reserved for the most critical targets. |
| Finding and exploiting individual zero-days | OC3 | Organized groups can buy zero-days from brokers or have dedicated vulnerability research teams. The underground zero-day market makes this accessible to well-funded criminals. |
| Direct physical access to sensitive systems | OC5 | Only nation-states with advanced infiltration capabilities, fake identities, and operational security can reliably penetrate secured facilities. Even then, modern data centers are challenging targets. |
| Bribes and cooperation | OC3 | Organized crime has the funds and experience to recruit insiders. A single corrupted employee with privileged access can be worth millions in stolen data or ransoms. |
| Social engineering | OC2 | Professional attackers have refined phishing and pretexting techniques. With weeks of reconnaissance and targeted campaigns, success rates are high even against security-aware organizations. |
| Intentional ML supply chain compromise | OC3 | Requires understanding of ML pipelines, access to training infrastructure, and ability to poison models subtly. Organized groups targeting AI companies have these capabilities. |
| Direct access to zero-days at scale | OC4 | Only nation-states can maintain arsenals of zero-days. Requires either internal discovery teams (expensive) or purchasing from specialized brokers at $500K-2M per vulnerability. |
| Model extraction | None | Never reaches score ≥4. Even state actors (OC5 score=3) struggle with modern model extraction defenses. The query budgets and computational requirements are prohibitive. |



**Key Insights:**
- Many "sophisticated" attacks (social engineering, exploiting known vulnerabilities) are actually accessible to low-level actors
- The jump from OC3 to OC4 represents the state/non-state divide - certain capabilities are simply unavailable without government resources
- AI-specific attacks vary widely: API access is easy but model extraction is hard; ML backdoors need specialized knowledge. However, **the report notes that these attacks may evolve very rapidly.**
- Physical security becomes critical at OC3+ when insider threats and sophisticated infiltration become realistic

</details>

After reviewing the answers, **read table TABLE 5.2 in the report directly.**.

**Then discuss:**

* Which attack vectors surprised you most in terms of who can/cannot execute them?
* Look at vectors that jump from low scores at OC3 to high scores at OC4. What capabilities do nation-states have that even well-funded criminal organizations lack?
* What does it tell us that model extraction through APIs never reaches high feasibility, even for nation-states? The report notes that "the nature of [AI-specific attack vectors] could change very rapidly." How should organizations plan for this uncertainty?
* If you had limited security budget and could only defend well against OC3, which attack vectors would keep you up at night (those where OC4+ has much higher capability)?

## 2️⃣ Security Levels
Another key contribution of the report is proposal of five security levels (SLs) corresponding to the five Operational Capacity levels. SL is broadly defined as the level of security a system requires to thwart the correspondigly capable operations.

While general frameworks for securing digital systems (such as
[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)) have recently trended away from using predefined security levels (guiding each organization to define its own security requirements instead), this is problematic in cases where the security of those organizations has broad societal implications, such as frontier AI.


### Exercise 2.1: Familiarize yourself with Security Levels

**Have a look at "FIGURE 6.1 The Five Security Levels" in the report.**

To list the concrete measures and policies, the authors considered five primary environments in which AI models need to be protected. **Can you guess what the environments to protect are?** You may find useful to recall the threat model of AI lab infrastructure we created in week 1.

<details>
<summary>Answer</summary>

The authors considered these environments:
* model training
* research environment (focusing primarily on research done with trained large-scale models — for example, fine-tuning—and not research done on smaller models)
* internal deployment (for the organization’s own use)
* public API deployment (including inference, outputting logprobs, and customer fine-tuning)
* on-premises deployment (where a separate organization runs the model independently).
</details>

### Exercise 2.2: SL3 security measures

**Read tables 6.1 and 6.2 (corresponding to SL1 and SL2) listing the basic security measures.** Do not read further for now.

**Now list what security measures are missing from SL1 and SL2 to protect from SL3 insider threat.** Timebox this to 15 minutes. List security measures from these subcategories:

* Weight Security: Weight Storage
* Weight Security: Permitted Interfaces
* Weight Security: Access Control
* Weight Security: Monitoring
* AI Model Resilience: Oracle Protection
* Security of Network and Other (Non-weight) Sensitive Assets: Access, Permissions, and Credentials
* Security of Network and Other (Non-weight) Sensitive Assets: Security Tooling
* Personnel Security: Awareness and Training
* Personnel Security: Filtering and Monitoring
* Threat Detection and Response: Placement of effective honeypots

After you are done, compare your answers with Table 6.3 in the report.

### Exercise 2.3: Current security levels
**Read through the rest of the security measures (Tables 6.3-6.5).**

Anthropic recently (May 2025) activated another level of protection from their Responsible Scaling Policy for the release of Claude Opus 4. Based on this, they updated their security program  with over 100 new controls including:

* **Egress bandwidth controls:** preliminary egress bandwidth controls the restrict the flow of data out of secure computing environments where AI model weights reside.
* **Two-party control:** Automates the requirement that any employee needing access to model weights must authenticate with a physical security key, provide a justification, and obtain authorization from a second party at the time of the request. Permission, when granted, is given for only a limited period.
* **Endpoint software control:** Binary allowlisting mechanisms. Along with their endpoint detection and response (EDR) software, it blocks execution of less sophisticated malware on Anthropic devices.
* **Change management for secure development:** Changes for code repositories containing model weights and security infrastructure such as requiring additional reviews on some changes, mandatory cryptographically signed commits, and designated team ownership for critical paths.
* 5-10% of employees dedicated to security.

**Based on these measures, what Security Level from the report do they comply with**?

<details>
<summary>Answer</summary>

Anthropic [activated AI Safety Level 3 (ASL-3)](https://www-cdn.anthropic.com/807c59454757214bfd37592d6e048079cd7a7728.pdf) from their Responsible Scaling Policy.

Section 3.1.1 of the linked document describes the threat actors considered in-scope for ASL-3:

<blockquote cite="https://www-cdn.anthropic.com/807c59454757214bfd37592d6e048079cd7a7728.pdf">The RSP identifies specific threat actors considered in-scope for ASL-3, including
hacktivists, criminal hacker groups, organized cybercrime groups, terrorist organizations,
corporate espionage teams, basic insiders, and undifferentiated attacks from
state-sponsored groups. Sophisticated insiders, state-compromised insiders, nation-state
attackers, and advanced persistent threat (APT)-level actors are considered out of scope for
ASL-3.</blockquote>

**This would correspond to something between SL2 and SL3 from the RAND report (SL3 includes insiders).**

</details>

<details>
<summary>Discussion</summary>

Skim through Chapter 3 of the [announcement](https://www-cdn.anthropic.com/807c59454757214bfd37592d6e048079cd7a7728.pdf) to get a better idea of what measures are already implemented on top of the [existing ones](https://trust.anthropic.com/controls).

* How does it match the expectations you may have had beforehand?
* What are the implication of Anthropic recently activating measures at levels SL2-3?

</details>

### Exercise 2.4: Mapping security measures to Security Levels

To revise the measures you read about above, let's try assigning some of them to the appropriate Security Level.

**For each security measure below, guess the minimum Security Level (SL)** where this measure becomes necessary for adequate protection against model weight theft. You'll then compare your guesses against the report findings.

| Security Measure | Minimum Required SL |
|------------------|-------------------|
| Centralized weight storage | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |
| Completely isolated network | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |
| Insider threat program | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |
| Confidential computing | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |
| Red-teaming with elite external team | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |
| Zero Trust architecture (any level) | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |
| Hardware-enforced output rate limits | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |
| Two independent security layers | <select><option>Please select</option><option>SL1</option><option>SL2</option><option>SL3</option><option>SL4</option><option>SL5</option><option>Not required</option></select> |


Then compare your answers with the key below.

<details>
<summary><b>Solution and Explanations</b></summary>

| Security Measure | Minimum Required SL | Explanation |
|------------------|-------------------|-------------|
| Centralized weight storage | SL2 | Enhanced security requires consolidating model weights into controlled repositories. Prevents weight sprawl across multiple systems and enables better access controls, auditing, and monitoring capabilities. |
| Completely isolated network | SL5 | Maximum security demands air-gapped systems with no network connectivity. Extreme measure that severely impacts operations but necessary when protecting against nation-state actors with advanced capabilities. |
| Insider threat program | SL3 | Advanced security must address sophisticated internal threats. Requires behavioral monitoring, background checks, access reviews, and incident response capabilities that go beyond basic employee vetting. |
| Confidential computing | SL4 | High security environments need protection of data in use, not just at rest and in transit. Requires specialized hardware (TEEs) and significant technical expertise to implement and maintain effectively. |
| Red-teaming with elite external team | SL3 | Advanced security demands validation against sophisticated attackers. Internal teams may miss blind spots that external experts with offensive security experience can identify through realistic attack simulations. |
| Zero Trust architecture (any level) | SL1 | Fundamental security principle needed even at basic levels. Zero Trust's "never trust, always verify" approach is essential for protecting valuable AI assets from the start, though implementation depth varies by SL. |
| Hardware-enforced output rate limits | SL4 | High security requires tamper-resistant controls that software-based solutions cannot provide. Hardware enforcement prevents bypassing rate limits through system compromise or insider manipulation. |
| Two independent security layers | SL3 | Advanced security requires defense-in-depth with redundant, independent controls. If one layer fails, the second provides backup protection against determined adversaries with multiple attack vectors. |


**Key Insights:**
* Early measures are foundational: Notice how Zero Trust appears at SL1 - modern security starts with fundamental architectural principles
* SL3 is a major transition point: This is where insider threats enter the picture, requiring organizational changes beyond just technical controls
* Hardware becomes critical at SL4+: Software-only solutions are insufficient against nation-state actors who may have zero-days and advanced persistent capabilities
* SL5 requires extreme isolation: The jump to "completely isolated network" shows why SL5 is considered currently infeasible for production systems

**More Insights:**
* Defense layers scale exponentially: 2 layers (SL3) → 4 layers (SL4) → 8 layers (SL5), reflecting the increasing sophistication of attackers
* Security levels are cumulative - Each level includes all measures from previous levels
* Diminishing returns are real - Going from SL3→SL4 costs exponentially more than SL1→SL2
* Perfect security is impossible - Even SL5 can only "plausibly claim" to thwart nation-states
* Trade-offs intensify at higher levels - SL4-5 require significant productivity/efficiency sacrifices

</details>


## 3️⃣ Economy of Attack and Defense
The RAND report estimates budgets for each OC level:

| Level | Budget | Team Size | Duration | Key Actors |
|-------|--------|-----------|----------|------------|
| **OC1** | Up to **$1,000** | 1 person | Several days | Hobbyist hackers, script kiddies |
| **OC2** | Up to **$10,000** | 1 person | Several weeks | Professional hackers, small groups |
| **OC3** | Up to **$1 million** | ~10 people | Several months | Crime syndicates, insiders, terrorists |
| **OC4** | Up to **$10 million** | ~100 people | ~1 year | Nation-state standard ops (100+ per year) |
| **OC5** | Up to **$1 billion** | ~1,000 people | Several years | Top-priority state operations |

Think through what this allows them, and what is the cost from the defender's perspective. Try to answer some of the questions below with a web search or a [Fermi estimate](https://www.lesswrong.com/posts/PsEppdvgRisz5xAHG/fermi-estimates) - do not spend more than 10 minutes on each!

**Offense:**

* How much does it cost to execute a successful compromise by planting a malicious USB device?
* How much can it cost to bribe an insider to steal sensitive assets in a big AI lab?
* How much does a zero-day exploit cost on the black market?

**Defense:**

* What is a bug bounty budget for a larger security-minded company?
* How much is lost in productivity by Air-Gapping a frontier model training?
* How much does an insider threat program cost?


<details>
<summary>Possible answers</summary>

(Most were generated by an LLM)

* How much to plant a malicious USB?
    * Attacker Costs: $200-$1000 per device; success rate 10%?;  social engineering/delivery: $5,000-$20,000; exploit payload development: $50,000-$250,000 (or purchase); Total attacker cost: $55,000-$270,000
* How much is a zero-day?
    * _"on average, the cost of exploits for remote code execution vulnerabilities amounted to $100,000"_ ([source](https://archive.is/2YGKU)); AI targets would likely come at a premium
    * ethics premium: black market often pays 2-10x more than bounties
    * see also [Dark Web Price Index](https://www.privacyaffairs.com/dark-web-price-index-2023/)
* How much is an insider?
    * considerations: salary in AI lab can be up to a $1 million/year, time to "befriend" employee, bribe multiplier (2-10x annual salary?), risk premium for illegal activity, legal/laundering costs, success probability: 10-30%? -> LLM estimate: $7M-$35M
* What is a bug bounty budget?
    * Google/Microsoft critical vulnerabilities: $25,000-$151,515 typically
    * "Google announced it has paid out $11.8 million to more than 600 security researchers who reported bugs in 2024" ([source](https://www.csoonline.com/article/3843143/google-paid-out-almost-120-million-to-bug-hunters-last-year.html))
    * Bug bounties for AI may be even higher - [Apple offers up to $1 million](https://archive.is/xn7lK)
* How much does an insider threat program cost?
    * _"The cost of insider risk continues to rise, with the annual average reaching $17.4M – up from $16.2M in 2023 – largely driven by increased spending on containment and incident response."_ ([source](https://www.dtexsystems.com/blog/2025-cost-insider-risks-takeaways/))

</details>

## 4️⃣ AI-Specific Considerations

This section contains some additional discussion topics (recommended in groups of 4 - ask a TA for guidance).

### 4.1 AI Control Capability Levels
Consider the context of [AI Control research agenda](https://www.alignmentforum.org/posts/kcKrE9mzEHrdqtDpE/the-case-for-ensuring-that-powerful-ais-are-controlled): searching for safety measures to prevent unacceptably bad outcomes, even if the AIs are misaligned and intentionally try to subvert those safety measures. An example of such safety measures are monitors - systems that consume the outputs of AI systems and flag those that seem malicious.

**What could be capability levels of AI systems relevant that require different monitoring measures?**

<details>
<summary>Reference answer</summary>
See Figure 1 in [this paper](https://arxiv.org/pdf/2504.05259)
</details>

### 4.2: Model weight theft
Compare traditional data exfiltration vs. model weight theft - what makes model weights special?

What are the different trad-eoffs for model extraction vs. direct theft trade-offs at different OC levels?


### 4.3: Insider threats
Why might insider threats (Human Intelligence category) be particularly concerning for AI labs?


"""
