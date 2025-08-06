# %%
"""
# W1D3 - Threat Modeling and Security Analysis

Today you'll learn about several systematic approaches to identifying and analyzing security threats. You'll practice threat modeling on AI infrastructure, create attack trees for real incidents, and have a look at capability matrices and safety cases.

Compared to ad-hoc security reviews, threat modeling and other systematic approaches will help you get into the shoes of an attacker and a defender, avoid gaps in security coverage, provide a common language for security discussions, and help prioritize threats based on risk and impact.


<!-- toc -->

## Content & Learning Objectives

### 1️⃣ STRIDE Threat Modeling

In the first set of exercises, you'll learn and apply the STRIDE methodology to systematically identify security threats in AI infrastructure.

> **Learning Objectives**
> - Understand the six categories of threats in STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
> - Create data flow diagrams that accurately represent system architecture and trust boundaries
> - Apply STRIDE analysis to identify, prioritize, and mitigate security threats

### 2️⃣ Attack Trees and Adversary Analysis

Here, you'll explore attack trees to understand how attackers think and plan their operations, using a real-world security incident as a case study.

> **Learning Objectives**
> - Construct attack trees that break down attacker goals into actionable steps
> - Analyze real security breaches (like the LastPass breach) to understand attack progression
> - Learn about different types of trees: attack trees, attack-defense trees, and game trees

### 3️⃣ Adversary Capability Modeling

In the final exercise, you'll learn to assess different threat actors' capabilities and match appropriate security controls to the threats you face.

> **Learning Objectives**
> - Categorize threat actors by operational capacity (resources, skills, motivation)
> - Create capability assessment matrices to evaluate attack feasibility

## Introduction to Threat Modeling

Threat modeling is the process of systematically identifying and rating threats to a system. It is a broad term that can encompass different approaches from systematic analysis of all threat surfaces, to estimates of threat actors' capabilities. What they have in common is taking the **attacker's perspective** and thinking about what can go wrong - this is the essence of **security mindset**.

In general, there are five major threat modeling steps:
- Defining security requirements.
- Understanding the system (What are we working on?)
- Identifying threats (What can go wrong?)
- Mitigating threats (What are we going to do about it?)
- Validating that threats have been mitigated (Did we do a good enough job?)

Threat modeling should not be a one-time activity, but an ongoing process. A **threat model is a living document** that should be updated regularly, as the system evolves and new threats emerge. The people working on a system should understand what changes to the system are security relevant, and model their impact before they are implemented. You will often find that it's the only kind of system documentation that is actually up to date (because it needs to be), making it quite useful for other purposes as well.

### Why Threat Modeling?
As a person responsible for security, you usually need to think through the steps in blue below. The purple steps show how the threat modeling steps can map to your responsibilities:

<img src="./resources/threat-modeling-high-level.png" alt="Threat Modeling Steps" style="margin: 20px;">


Compared to more ad-hoc security reviews, threat modeling can help you
- Take different perspectives and spot things you may otherwise miss
- Identify highest-priority threats and mitigations so that you can allocate your resources effectively
- Maintain an up-to-date model of your system


<details>
<summary>Vocabulary: Threat Modeling Terms</summary>

- **Asset**: Something of value that needs protection (data, systems, reputation)
- **Threat**: A potential negative event or actor that could harm assets
- **Threat Actor**: An individual or group that could pose a threat
- **Vulnerability**: A weakness that could be exploited by a threat
- **Risk**: The potential for loss or damage to an asset; risk is at the intersection of assets, threats, and vulnerabilities
- **Mitigation**: Actions taken to reduce risk
- **Attack Surface**: The sum of all points where an attacker can try to enter or extract data
- **Attack Vector**: The method or pathway used to exploit a vulnerability (e.g., SQL injection to exploit a database input validation vulnerability)
- In other words: Threat Actors exploit Vulnerabilities through Attack Vectors against Assets, creating Risks that require Mitigations.

</details>

## STRIDE Methodology

[STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#stride-model) is a framework that categorizes threats into six types:

- **S**poofing: Pretending to be someone or something else, including through stolen credentials
- **T**ampering: Modifying data or systems without authorization
- **R**epudiation: Denying actions or claiming others performed them
- **I**nformation Disclosure: Exposing information to unauthorized parties
- **D**enial of Service: Making systems unavailable to legitimate users
- **E**levation of Privilege: Gaining unauthorized access levels

A STRIDE-based threat model usually includes:

- **List of assets to be protected**
- **Model of the system** under review, usually expressed as a **data flow diagram**,
- **List of threats and mitigations**, along with relevant details like assumptions about the system and external dependencies, known risks, and **priorities** (based on likelihood, impact)
- Sometimes also a **list of use cases** for the system and/or a **list of malicious actors**
- **Validation information**, e.g., tracking the implementation of mitigations, or feedback from the team

Here is the process step by step:

**Step 1:** Create a **data flow diagram** of the system.

<img src="./resources/dfd-components.drawio.png" alt="Data Flow Diagram" width="400" style="margin: 20px;">

It should:
- contain all relevant **components, actors, and data stores** as nodes
- connect the nodes with **arrows indicating the flow of data**, annotated with what kind of data
     - unlike in other architectural diagrams, these are _not_ dependencies nor calls - the direction of the arrow indicates in what direction the data is flowing
- indicate **trust boundaries** (areas with different privilege levels or trust assumptions)

Here is an example of what a data flow diagram could look like for a public facing infrastructure of a simple LLM chatbot:

<img src="./resources/dfd-example.drawio.png" alt="Chatbot Data Flow Diagram" width="600" style="margin: 20px;">

**Step 2:** For each data flow, and think about what **threats from each STRIDE category** above are relevant for it. It is often useful to go through the categories for data stores as well. Once you have the list, prioritize it and propose relevant risk mitigations.

Here is an example of a table recording the results:

<table style="width: 100%; border-collapse: collapse; font-size: 14px;">
<thead>
<tr style="background-color: #f0f0f0;">
    <th style="border: 1px solid #ddd; padding: 8px; width: 15%;">Data Flow / Asset</th>
    <th style="border: 1px solid #ddd; padding: 8px; width: 8%;">Category</th>
    <th style="border: 1px solid #ddd; padding: 8px; width: 20%;">Threat</th>
    <th style="border: 1px solid #ddd; padding: 8px; width: 8%;">Likelihood</th>
    <th style="border: 1px solid #ddd; padding: 8px; width: 7%;">Impact</th>
    <th style="border: 1px solid #ddd; padding: 8px; width: 7%;">Priority</th>
    <th style="border: 1px solid #ddd; padding: 8px; width: 20%;">Controls / Mitigations</th>
    <th style="border: 1px solid #ddd; padding: 8px; width: 15%;">Validation</th>
</tr>
</thead>
<tbody>
<tr>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;"><strong>Customer browser → API Gateway</strong></td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">Spoofing</td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">Attacker uses stolen API keys to impersonate legitimate users and access proprietary models</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top;">High</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top;">Medium</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top; background-color: #ffdddd;"><strong>High</strong></td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
        • Rate limiting per key<br>
        • Anomalous usage monitoring
    </td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
        • Test rate limits<br>
        • Review anomaly alerts monthly
    </td>
</tr>
<tr style="background-color: #f9f9f9;">
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;"><strong>Training Data → GPU Cluster</strong></td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">Tampering</td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">Malicious actor poisons training dataset by injecting backdoored samples through compromised researcher account</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top;">Medium</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top;">High</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top; background-color: #ffdddd;"><strong>High</strong></td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
        • Data versioning with checksums<br>
        • Approval for dataset changes<br>
    </td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
    </td>
</tr>
<tr>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;"><strong>Model checkpoints (S3 Storage)</strong></td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">Information Disclosure</td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">Model checkpoints of sensitive models exposed through storage provider compromise</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top;">Medium</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top;">Critical</td>
    <td style="border: 1px solid #ddd; padding: 8px; text-align: center; vertical-align: top; background-color: #ffdddd;"><strong>High</strong></td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
        • Enable S3 encryption at rest (SSE-S3)<br>
        • Minimum privileges and monitoring of decryption key usage
    </td>
    <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
        • Scan for unencrypted objects<br>
    </td>
</tr>
</tbody>
</table>


<details>
<summary>Tips for Data Flow Diagrams</summary>

- Do not forget about all entry points (avoid magic sources and sinks).
- Collapse similar elements into one - if they have the same data flows and are in the same trust boundary, they should be just one node.
- Limit your scope. If you are modeling a larger system, create an overview diagram with high-level flows between subsystems, and model each subsystem separately.
- In practice, it is often useful to also annotate the data flows with authentication information (e.g., "static API key", "SSO token"), and data stores with data classification (e.g., public, private, sensitive).

</details>

<details>
<summary>When to apply STRIDE</summary>

- It is relatively easy to learn and use
- Very useful for identifying threats that may missed with a less systematic approach
- On the other hand, it can be quite time consuming
- It is software centric and does not fit situations where other perspectives are relevant
- Best for limited scopes (e.g., a new feature), or for ongoing threat modeling of a system

</details>

For a realistic example of a STRIDE analysis, see [this excellent post from NCC Group](https://archive.is/TLUzE).

### Exercise 1: Understanding STRIDE

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵🔵🔵⚪⚪

Let's practice applying STRIDE to a simple scenario. Consider a web-based AI model API where users submit text and receive predictions.

**For each STRIDE category, identify one potential threat.**  Example:
* *Spoofing*: An unauthorized service could mimic the API endpoint, tricking users into sending their text input to a malicious system.

(Only expand the solution below after you have tried yourself:)

<details>
<summary>Solution</summary>

- **Spoofing**: Attacker uses stolen API keys to impersonate legitimate users
- **Tampering**: Attacker modifies prediction requests in transit to poison the model
- **Repudiation**: User claims they never made certain API calls to avoid charges
- **Information Disclosure**: API errors reveal model architecture or training data
- **Denial of Service**: Attacker floods API with requests to exhaust compute resources
- **Elevation of Privilege**: User exploits API to access admin functions or other users' data

</details>

## AI Lab Infrastructure Threat Model

Now let's work on a threat modeling exercise for an AI research lab.

### Scenario Description

You're the security lead for an AI research lab. Your goal is to create a threat model for part of the lab's infrastructure.

Use cases to model:
* **Customers** can prompt internal frontier models to get a LLM completion.
* **Researchers** can run experiment jobs on the compute cluster with access to frontier models inference.
* **Researchers** can examine experiment results in a UI.
* **External collaborators** can submit experiment jobs to the compute cluster.

The lab has the following infrastructure:
- The lab provides **inference services** on top of its **frontier models** through a **public API**.
- Code and configuration for **evaluation experiment jobs** can be submitted to and will be scheduled to run by a **job orchestration service** (the lab uses Kubeflow for this).
- The jobs can write **experiment results** to **Weights and Biases** (an experiment tracking service). Researchers can access the results in its UI.
- The evaluation experiment jobs call the inference service.
- The lab also has a separate **training infrastructure** that produces the frontier model weights, and **small model weights** that researchers can access directly from evaluation experiment jobs.

Additional security requirements include:
- The model weights of the frontier models **must not** be directly available to any of the actors considered in this threat model. Small models **can** be accessed directly from experiment jobs.

Out of scope:
- CI/CD and deployment of the infrastructure.
- Training infrastructure (treat it as a black box)
- Customer facing infrastructure other than the inference API.
- Monitoring and prevention of inference misuse by customers.

### Exercise 2: Identify Assets to Protect

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵⚪⚪⚪⚪

List the key assets that need protection in this AI lab.

<details>
<summary>Hint</summary>

Consider:
- Data assets
- Model/IP assets
- Infrastructure assets
- Reputation/trust assets

</details>

<details>
<summary>Reference solution</summary>

The solutions for this and subsequent exercises are not unique, there can be different ways to approach them.
We are also making some simplifying assumptions, e.g., we are omitting customer data that may be recorded in practice.

**Assets to protect:**
- Frontier model weights
- Small model weights
- Experiment results and logs
- Algorithmic secrets - model architectures, experiment code
- API keys and authentication credentials
- Availability of compute resources
- Availability of inference services and public APIs
- Public reputation of the lab
</details>


### Exercise 3: Create a Data Flow Diagram of AI Lab Infrastructure

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪

Create a **data flow diagram (DFD)** of the AI lab infrastructure described above that will be suitable for STRIDE analysis.

**Step 1: Start with the inference infrastructure, ignore the evaluation experiment use cases for now.**

We recommend [draw.io](https://www.drawio.com/blog/threat-modelling) to create the DFD, but you can use any diagramming tool you are comfortable with (including whiteboard, or pen and paper!).

You can omit details for training and customer facing infrastructure (treat them as black box subsystems -  it's ok to model them in separate diagrams later!).


<details>
<summary>Hint 1</summary>

You can start, e.g., from the actor(s) and the use case. What data do they write or read to accomplish their use cases? Where is the data stored?

</details>

<details>
<summary>Hint 2</summary>
Don't forget to think about all entry points. Avoid magic data sources and sinks - all data needs to come from somewhere.

Add relevant trust boundaries.
</details>

<details>
<summary>Reference solution for step 1</summary>
Open the diagram below after you have created your own, and compare the two. What could you have done differently? What are the pros and cons?

<a href="./resources/reference-dfd-part1.drawio.png">Reference solution</a>

The data flows are annotated with the authentication information. You are not required to include this but it's often helpful later.

A frequent source of confusion is the direction of the data flow arrows. Remember that the arrow indicates the direction of the data flow, not dependencies or calls. It is not always clear what to use with request/response flows; you can use one arrow for each direction, or whatever you find helpful for your stakeholders.
</details>

**Step 2: Add details for the evaluation experiment use cases.** Finish the data flow diagram by adding details about the  experiment infrastructure. You can still treat training as a black box.


<details>
<summary>Hint 1</summary>

Make sure you covered all the infrastructure mentioned in the description. Some details may be missing - in practice, you would need to clarify with the team, but for the purpose of this exercise, just make your own assumptions.

You don't need to capture every microservice or component in the diagram as a separate node though. Keep just enough detail to help you analyze the attack surface.
</details>

<details>
<summary>Reference solution for step 2</summary>
As in the other exercises in this section, there can be many different solutions.

Open the diagram below after you have created your own, and compare the two. What could you have done differently? What are the pros and cons?

<a href="./resources/reference-dfd.drawio.png">Reference solution</a>

Note that the reference solution is not perfect - we are making some simplifying assumptions, e.g., we omited how external collaborators get their accounts created or how they get the experiment results. It's ok to start with something and iterate on details later!

Also note the diagram should capture an **actual state** of things, not the ideal state. So while we modeled sensitive inference infrastructure as a separate trust boundary (implying, e.g., network level isolation, or a separate cluster), this may not be the case in practice!

</details>

### Exercise 4: Apply STRIDE Analysis

> **Difficulty**: 🔴🔴🔴🔴🔴
> **Importance**: 🔵🔵🔵🔵⚪

Now that we have a model of our system, let's apply STRIDE analysis to it.

**Step 1: External Collaborator → Job Orchestration data flow**:
Start with this data flow (if this is not present in your solution of the previous exercise, look at the <a href="./resources/reference-dfd.drawio.png">reference solution</a>). Create a table with the following columns:

* *Data Flow / Asset* ("External collaborator → Job orchestration")
* *Category* ("Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege")
* *Threat* (description of the threat considered)

Try to think about threats related to the data flow and add **at least one line for each of the STRIDE categories**.

*Tip: The threat should describe who the actor is, what damage they cause, and how. You don't need to be too specific though, e.g., you don't need to known how to carry out a man-in-the-middle attack exactly to list it as a threat.*

Once you're done, have a look at the reference solution below and compare your results.

<details>
<summary><b>Reference solution for step 1</b></summary>

Here is an example of threats for the External Collaborator → Job Orchestration data flow.

* How does it compare to what you considered?
* Would you have come up with the same threats if you didn't go through the STRIDE categories?

<table>
<thead>
<tr>
    <th style="background-color: #f0f0f0;">Data Flow / Asset</th>
    <th style="background-color: #f0f0f0;">Category</th>
    <th style="background-color: #f0f0f0;">Threat</th>
</tr>
</thead>
<tbody>
<tr style="background-color: #f9f9f9;">
    <td rowspan="6"><strong>External collaborator → Job orchestration</strong><br><em>(Kubeflow)</em></td>
    <td>Spoofing</td>
    <td>Unauthorized user gains access by stealing or forging collaborator credentials</td>
</tr>
<tr>
    <td>Tampering</td>
    <td>Malicious actor submits job configurations designed to corrupt experimental model weights or training pipeline</td>
</tr>
<tr style="background-color: #f9f9f9;">
    <td>Repudiation</td>
    <td>User denies submitting expensive compute jobs to avoid accountability</td>
</tr>
<tr>
    <td>Information Disclosure</td>
    <td>Job submission interface leaks information about other users' experiments or available compute resources</td>
</tr>
<tr style="background-color: #f9f9f9;">
    <td>Denial of Service</td>
    <td>Malicious collaborator submits resource-intensive jobs to monopolize compute cluster</td>
</tr>
<tr>
    <td>Elevation of Privilege</td>
    <td>External collaborator exploits job submission to gain unauthorized access to sensitive model weights or other users' experiments</td>
</tr>

</tbody>
</table>
</details>

**Step 2: Add priorities and mitigations**:
For the table you created, add a *Priority* (Low/Medium/High/Critical) and a *Mitigations* column. Fill in the values. (If it helps, you can break down the priority into *Likelihood* and *Impact*).

Once you're done, have a look at the reference solution below and compare your results.

<details>
<summary><b>Reference solution for Step 2</b></summary>

Look at the following STRIDE analysis and compare it to your own. Again, you may have come up with results, this exercise does not have a single correct answer.

In practice, you may have limited time to go into details. That's why it's important to prioritize the threats and start with the most critical ones.

Note that mitigations can repeat across different threats, and they themselves can be of different importance! Creating a prioritized backlog of mitigations would be a next step after the analysis, as well as regularly tracking progress on them. Threat priorities will be helpful again when you review the progress.

<table>
<thead>
<tr>
    <th style="background-color: #f0f0f0;">Data Flow / Asset</th>
    <th style="background-color: #f0f0f0;">Category</th>
    <th style="background-color: #f0f0f0;">Threat</th>
    <th style="background-color: #f0f0f0;">Likelihood</th>
    <th style="background-color: #f0f0f0;">Impact</th>
    <th style="background-color: #f0f0f0;">Priority</th>
    <th style="background-color: #f0f0f0;">Mitigations</th>
    <th style="background-color: #f0f0f0;">Validation</th>
</tr>
</thead>
<tbody>
<tr style="background-color: #f9f9f9; vertical-align: top;">
    <td rowspan="8"><strong>External collaborator → Job orchestration</strong><br><em>(Kubeflow)</em></td>
    <td>Spoofing</td>
    <td>Unauthorized user gains access by stealing or forging collaborator credentials</td>
    <td>Medium</td>
    <td>High</td>
    <td style="background-color: #ffdddd;"><strong>High</strong></td>
    <td>• SSO with MFA enforcement<br>
        • Session timeout policies<br>
        • IP allowlisting for known collaborators<br>
        • Regular credential rotation</td>
    <td>• Failed login monitoring<br>
        • Quarterly access reviews</td>
</tr>
<tr style="vertical-align: top;">
    <td>Tampering</td>
    <td>Malicious actor submits job configurations designed to corrupt experimental model weights or training pipeline</td>
    <td>Low</td>
    <td>High</td>
    <td style="background-color: #ffffdd;"><strong>Medium</strong></td>
    <td>• Code review requirements before a job from external collaborators is executed<br>
        • Read-only access to model weights<br>
        • Job execution in isolated environments</td>
    <td>• Monitor for anomalous jobs (e.g., what permissions they use, network traffic)<br>
        • Regular job execution audits</td>
</tr>
<tr style="background-color: #f9f9f9; vertical-align: top;">
    <td>Repudiation</td>
    <td>User denies submitting expensive compute jobs to avoid accountability</td>
    <td>Medium</td>
    <td>Low</td>
    <td style="background-color: #ddffdd;"><strong>Low</strong></td>
    <td>• Tamper-proof audit logs<br>
        • Job attribution tracking<br>
        • Digital signatures on job submissions</td>
    <td>• Regular log integrity checks<br>
        • Quarterly job submission reviews</td>
</tr>
<tr style="vertical-align: top;">
    <td>Information Disclosure</td>
    <td>Job submission interface leaks information about other users' experiments or available compute resources</td>
    <td>Medium</td>
    <td>Medium</td>
    <td style="background-color: #ffffdd;"><strong>Medium</strong></td>
    <td>• Access control on job metadata<br>
        • Tenant isolation in Kubeflow<br>
        • Encryption in transit<br>
        • Data classification and labeling</td>
    <td>• Penetration testing<br>
        • API security scanning<br>
        • Regular access control audits</td>
</tr>
<tr style="background-color: #f9f9f9; vertical-align: top;">
    <td>Denial of Service</td>
    <td>Malicious collaborator submits resource-intensive jobs to monopolize compute cluster</td>
    <td>High</td>
    <td>Medium</td>
    <td style="background-color: #ffdddd;"><strong>High</strong></td>
    <td>• Rate limits and quotas<br>
        • Resource allocation policies<br>
        • Job priority queuing<br>
        • Resource reservation for critical jobs</td>
    <td>• Resource usage monitoring<br>
        • Anomaly detection alerts<br>
        • Regular capacity planning reviews</td>
</tr>
<tr style="vertical-align: top;">
    <td>Elevation of Privilege</td>
    <td>External collaborator exploits job submission to gain unauthorized access to sensitive model weights or other users' experiments</td>
    <td>Medium</td>
    <td>Critical</td>
    <td style="background-color: #ffdddd;"><strong>High</strong></td>
    <td>• Network isolation of sensitive compute infrastructure<br>
        • Job sandboxing and resource quotas<br>
        • Access control with minimum privileges needed for the job to run<br>
        • Access control on experiment results<br>
        • Container security policies</td>
    <td>• Penetration testing annually<br>
        • Automated security testing of network isolation configuration<br>
        • Regular privilege escalation testing</td>
</tr>

</tbody>
</table>
</details>

**Step 3: Continue with the analysis for other data flows and/or data stores**:
You can continue practicing STRIDE analysis for other data flows and/or data stores. Going through all of them would be time consuming (though you'll get better at it with practice, and some will be similar), so pick only one or two additional flows or stores to analyze. The reference solution contains threats for "Evaluation Experiment Jobs → Experimental Model Weights" flow and "Sensitive Model Weights" data store - you can choose these if you want to compare your results against them.

One you're finished, you can have a look at the reference solution.

<details>
<summary><b>Reference solution for Step 3</b></summary>

<a href="./resources/stride-reference-solution.html">Reference solution</a>

Congratulations, you have finished your first threat model!

Discuss with your partner how useful you found the exercise. Did it bring value beyond a less structured modeling you may have done? When would this approach be suitable and when not?
</details>

## Attack Trees

In the previous section, we analyzed systems from a defensive perspective using STRIDE - starting with the system architecture and identifying potential threats. Now we'll explore **attack trees**, which take the opposite approach: starting with an attacker's goals and breaking them down to understand the steps they might take to achieve them. This approach can help security teams to focus on the most likely attack paths and prioritize defenses accordingly. Attack trees can also be reusable between different systems.

### Types of Attack Trees
There are several related types of trees used in security analysis, all of which can be formalized as rooted trees with nodes representing states of the game or decision points.

-  Classic **Attack Trees** break down an attacker's primary goal into subgoals and specific actions. The tree structure shows how different attack methods can be combined to achieve the ultimate objective and what alternative paths are possible.
- **Attack-Defense Trees** extend classic attack trees by incorporating defender responses.
- **Game Trees** are a special case where attackers and defenders take turns, with each side responding to the other's latest strategy. Leaves of the tree can contain payouts for the attacker/defender so that we can find optimal strategies by working backwards from the end of the game.

### Visual Examples

Let's examine some concrete examples to understand how these trees work in practice.

The first example is a simple **attack tree** demonstrating a physical infrastructure attack:

<img src="./resources/attack-tree-simple.drawio.png" alt="Simple Attack Tree" width="400"/><br>
<sub>Source: [amenaza.com](https://www.amenaza.com/attack-tree-what-are.php)</sub>

You can see several kinds of nodes:
- "AND" nodes (blue half-circles) - require all children to succeed ("Gain physical access AND disable security system")
- "OR" nodes (green crescents) - require any child to succeed ("Pick lock OR break window")
- Leaf nodes - specific actions or attack techniques the attacker can execute.

<details>
<summary>More examples</summary>
For a more complex example, you can look at this [DNS attack tree](./resources/dns-attack-tree.svg) from [attacktree.online](https://attacktree.online/).

</details>

The next example is an **attack-defense tree** demonstrating an attack on a bank account, with response by the defenders in green boxes (it uses a different notation - don't get confused by this, the idea is the same).

<img src="./resources/attack-defense-tree.png" alt="Attack-Defense Tree" width="400"/><br>
<sub>Source: [satoss.uni.lu](https://satoss.uni.lu/members/barbara/papers/adt.pdf)</sub>

A **Game tree** could look similar to the attack-defense tree, with nodes on each path from root to leave alternating between defender and attacker. For an example of a game-tree like analysis in the context of designing AI control protocols, see [Ctrl-Z: Controlling AI Agents via Resampling](https://www.bashcontrol.com/#:~:text=The%20Game%20Tree%20of%20Untrusted%20Monitoring).


### Exercise 5: LastPass breach attack tree

> **Difficulty**: 🔴🔴🔴🔴⚪
> **Importance**: 🔵🔵🔵🔵⚪

In 2022, sophisticated attackers compromised LastPass, one of the world's most popular password managers. The attackers gained initial access by exploiting a software vulnerability on a DevSecOps engineer's computer, stole their credentials, and ultimately exfiltrated encrypted customer password vaults, source code repositories, and unencrypted customer metadata. Although the attackers could only steal encrypted vault data, the breach was later linked to later cryptocurrency theft from customers' accounts.

Your goal in this exercise is to analyze what steps the attacker could have taken to achieve their goals.

1. You will get a description of the LastPass infrastructure
2. You will propose first two layers of the attack tree.
3. We'll then show you the reference solution for the first two layers so that you can compare your results.
4. You will then propose the rest of the attack tree.
5. Finally, we'll show you the reference solution with details of the actual attack.

#### LastPass infrastructure
LastPass operates a **cloud-based architecture** using Amazon Web Services (**AWS**) for both **development and production environments**. The company maintains separate cloud-based development environments where engineers work on **source code**, and production systems that store live customer data in **AWS S3 storage buckets**.

Senior DevSecOps engineers have privileged access to a corporate vault containing critical decryption keys and production credentials. The development environment contains several code repositories.

Customer password vaults are stored in the production environment, and **encrypted backups** are located in shared cloud storage. Each vault is encrypted using a unique key derived from the user's master password. LastPass also stores customer metadata including usernames, email addresses, billing addresses in both encrypted and unencrypted formats. The company uses AWS GuardDuty for security monitoring and anomaly detection across their cloud infrastructure.

#### Attacker goals
The attackers' primary objective was to steal LastPass customer password vault data. The attackers also sought to exfiltrate customer metadata and personally identifiable information that could be monetized through data brokers or used for targeted attacks against high-value individuals. To achieve these goals, the attackers needed to progress from initial access, to LastPass's cloud infrastructure, then escalate from development systems to production data storage.


#### Creating attack tree
**Step 1 - First two layers**:
Start with the primary objective as the root node, and brainstorm the first two layers of an attack tree modeling possible attacker's subgoals below it. Again, you can use [draw.io](https://www.drawio.com/blog/threat-modelling) or any other tool (including pen and paper) to create the tree.

When you're done, have a look at the reference solution below and compare your results.

<details>
<summary><b>Reference solution for Step 1</b></summary>
Have a look at the <a href="./resources/lastpass-step1.html">reference solution</a> created based on the actual attack.


(It's using a slightly different notation to make it more convenient to create with Mermaid diagrams - don't worry if you used a different notation.)

</details>

**Step 2 - Rest of the tree**:
You may update your tree with details from the reference solution above.
Then continue creating rest of the attack tree.

This is an open-ended exercise, so we recommend you set a short timebox so that you don't end up going into unnecessary details.

When you're done, have a look at the reference solution below and compare your results.

<details>
<summary><b>Reference solution for Step 2</b></summary>

Have a look at the <a href="./resources/lastpass.html">reference solution</a> created based on the actual attack.

Note that the leaves are annotated with details of the actual attack. This is not a standard part of an attack tree (because it models a hypothetical attack, not a real one). We only added it to give you more context about the attack.

It is not expected that you have created an identical tree - the attacker could have taken a very different path! The purpose of the reference solution is to give you an idea of what realistic attack paths could look like.

Discussion points:
- How does this attack tree compare to the one you created? What surprises you?
- How does this approach compare to STRIDE approach you saw in the previous section? How are they different in the thoroughness of attack surface coverage, and time required?

</details>

<details>
<summary>Notes on the LastPass attack</summary>

Besides being an interesting case study for threat modeling, the LastPass breach is also an iteresg example of attack by an advanced actor:

- **Multi-phase:** The breach required successful completion of both initial access and data storage access phases
- **Targeted Approach:** Rather than broad attacks, attackers specifically targeted DevSecOps engineers with high-privilege access
- **Lateral Movement:** Initial development environment access was leveraged to find pathways to production customer data
- **Applied techniques:** The attack exploited a known vulnerability in third-party software that should have been patched, used a keylogger to bypass MFA, credential harvesting for excalation of privilege, used a VPN to hide the origin of the activity and bypass intrusion detection, etc.
- **Post-breach activity:** Besides the initial break, the attackers likely used the stolen customer data to carry out further attacks and monetize it.
</details>


## Adversary Capability Modeling
Understanding the capabilities of different threat actors is helpful for prioritizing security investments. A good example of from practice in the context of AI is the RAND report Securing AI Model Weights (don't look it up just yet).

Among other things, the report defines five **"operational capacity" (OC)** categories based on the resources and capabilities available to the respective threat actors. Based on this, they propose five **security levels (SL1 to SL5)** providing protection from the correspondingly capable operation. An AI lab can then choose the appropriate security level to aim for depending on the sensitivity of assets it works with.

RAND's methodology follows these steps:
1. Identify the operational capacity categories
2. Compile a list of potential attack vectors relevant for model weights access
3. Create a **capability assessment matrix** - with estimates of likelihood that an actor from a given OC category can execute a given attack vector successfully
4. Defined the five security levels required to secure a system against each of the five OC categories (based on the capability assessment)

In this section, we'll try to recreate part of the report results.

### Exercise 6: Identifying operational capacity categories

> **Difficulty**: 🔴🔴⚪⚪⚪ **Importance**: 🔵🔵⚪⚪⚪

Try to come up with the five OC categories of threat actors. Try to answer the following questions about each:
- What is the actor's budget?
- What is the manpower available to them? Where do the members come from?
- What is the technical expertise available to them?
- What are examples of individuals or groups that belong to this category?
- What does a typical operation for this category look like?

The recommended time to spend on this exercise is 5-10 minutes. When you're done, have a look at the reference solution below and compare your results.


<details> <summary>Reference Solution</summary>

<a href="./resources/rand-oc.pdf">Operational capacity categories from the original report</a>

How closely did you come to the original solution?

</details>


### Exercise 7: Capability Assessment Matrix

> **Difficulty**: 🔴🔴🔴⚪⚪ **Importance**: 🔵🔵⚪⚪⚪

Using the RAND framework, assess the feasibility (1-5 scale) of these attack vectors for each threat actor level. Feasibility 1 means likelihood of success is 0-20%, 5 means 80-100%.

||Attack Vector|OC1|OC2|OC3|OC4|OC5|
|---|---|---|---|---|---|---|
|1|Exploiting vulnerabilities for which a patch exists||||||
|2|Exploiting reported but not (fully) patched vulnerabilities||||||
|3|Finding and exploiting individual zero-days||||||
|4|Social engineering for credentials||||||
|5|Password brute-forcing and cracking||||||
|6|Intentional ML supply chain compromise||||||
|7|Model extraction (through API)||||||
|8|Model distillation||||||
|9|Direct physical access to sensitive systems||||||
|10|Bribes and cooperation (with insiders)||||||

<details> <summary>Reference Solution</summary>

Here are the results from the original report:

<table style="border-collapse: collapse; width: 100%;">
  <thead>
    <tr>
      <th>#</th>
      <th>Attack Vector</th>
      <th>OC1</th>
      <th>OC2</th>
      <th>OC3</th>
      <th>OC4</th>
      <th>OC5</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1</td>
      <td>Exploiting vulnerabilities for which a patch exists</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
    </tr>
    <tr>
      <td>2</td>
      <td>Exploiting reported but not (fully) patched vulnerabilities</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
    </tr>
    <tr>
      <td>3</td>
      <td>Finding and exploiting individual zero-days</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
    </tr>
    <tr>
      <td>4</td>
      <td>Social engineering for credentials</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
    </tr>
    <tr>
      <td>5</td>
      <td>Password brute-forcing and cracking</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
    </tr>
    <tr>
      <td>6</td>
      <td>Intentional ML supply chain compromise</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
    </tr>
    <tr>
      <td>7</td>
      <td>Model extraction (through API)</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
    </tr>
    <tr>
      <td>8</td>
      <td>Model distillation</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ffe6e6;">2</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
    </tr>
    <tr>
      <td>9</td>
      <td>Direct physical access to sensitive systems</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
      <td style="color:black; text-align: center; background-color: #ffcccc;">3</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
    </tr>
    <tr>
      <td>10</td>
      <td>Bribes and cooperation (with insiders)</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: white;">1</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff9999;">4</td>
      <td style="color:black; text-align: center; background-color: #ff6666;">5</td>
    </tr>
  </tbody>
</table>

**Do you find anything surprising about these results?**

The full RAND report can be found here: [Securing AI Model Weights](https://www.rand.org/pubs/research_reports/RR2453.html).
</details>


## Bonus exercise: AI Lab Infrastructure Attack Tree

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵⚪⚪⚪

Similar to *Exercise 5: LastPass breach attack tree*, create an attack tree for the AI lab infrastructure described in the [AI Lab Infrastructure Threat Model](#ai-lab-infrastructure-threat-model). Timebox this exercise to 15 minutes to make sure you don't get into unnecessary details.

After you're done, you can compare your result with one possible solution below

<details>
<summary>Solution Example</summary>

<a href="./resources/ai-lab-attack-tree.html">AI Lab Infrastructure Attack Tree</a>

Discussion points:
- If you were to create a prioritized list of mitigations from this threat modeling exercise, how would go about it?
- How would a prioritized list of things to do created from this model be different from the STRIDE approach?

</details>


## Further reading
If you'd like to learn more about threat modeling, here are a few useful resources:
- For practical lightweight threat modeling, I recommend this [one page template](https://saweis.net/threatworksheet/threat-worksheet.pdf) by Stephen Weis.
- [Awesome Threat Modelling](https://github.com/hysnsec/awesome-threat-modelling) is a collection of more links to books, tutorial, tools, and [examples](https://github.com/hysnsec/awesome-threat-modelling?tab=readme-ov-file#threat-model-examples).
-For a realistic example of a STRIDE analysis, see this [this excellent post from NCC Group](https://archive.is/TLUzE).
- An interesting example relevant for AI are the in-depth [design reviews, threat models and attack trees **for Pytorch**](https://github.com/xvnpw/sec-docs/tree/main/python/pytorch/pytorch) by Marcin Niemiec
- Microsoft also provides some [guidance for modeling AI/ML systems](https://learn.microsoft.com/en-us/security/engineering/threat-modeling-aiml)
- [Threat modeling shape library](https://www.drawio.com/blog/threat-modelling) for diagramming with draw.io.
"""
