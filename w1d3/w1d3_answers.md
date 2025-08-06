# Exercise 1

Spoofing: steal api keys and using it then pretending being the owner of them
Tampering: Modifying the request or the response so either the inference or the response back is clobbered
Repudiation: Modifying request headers to pretend make request as a different user agent and from a different IP / domain than you are
Information Disclosure: API behavior can leak information about the code under the hood, like errors or data models
Denial of Service: trying to DDOS the service by flowding with requests
Elevation of Privilege: if there are admin endpoint poorly protected unauthorized users can try to exploit them to do forbidden operations

# Exercise 2

Assets are:
  - training data
  - model weight and biases
  - results of training run
  - logs of the runs
  - protect clusters with credentials
  - identity of people
  - availability protection
  - ideas and algorithm

# Excercise 3

pen & paper

# Exercise 4

| Flow                | STRIDE                       | Threat Example                                               | Likelihood | Impact | Priority    | Mitigation                                                   |
| ------------------- | ---------------------------- | ------------------------------------------------------------ | ---------- | ------ | ----------- | ------------------------------------------------------------ |
| External - Job orch | Spoofing                     | Steal session cookies from collaborator                      | medium     | High   | Medium/High | SSO / 2FA / IP whitelisting                                  |
| External - Job orch | Tampering                    | provide malicious configuration or code to make the pipeline fails or corruption weight in some way | low        | Medium | low         | RO model weight / Permision / code signing                   |
| External - Job orch | Repudiation                  | collab denies to have supplied evals                         | low        | low    | low         | unfalsifiable log                                            |
| External - Job orch | Information <br />Disclosure | UI is showing other collaborator experiments                 | medium     | medium | medium      | Good access control / Resources segregation                  |
| External - Job orch | DOS                          | flowd the server of job request                              | high       | low    | medium      | IP Whitelisting / Request throttling / Queue priority        |
| External - Job orch | Privilege esc                | if big misconfiguration of service maybe by supplying a config experiment you would gain access to weight or so | low-medium | high   | high        | Good access control / Network isolation / Privileged application isolation |


# Exercise 5

pen & paper

# Exrcerice 6

What is the actor's budget?
What is the manpower available to them? Where do the members come from?
What is the technical expertise available to them?
What are examples of individuals or groups that belong to this category?
What does a typical operation for this category look like?

SL1:
  - Budget: 1000$
  - 1 person junior
  - Any amateur hacker
  - Scripting / Analyzing public leaks / phishing
SL2:
  - Budget: 10,000$
  - 1 professional hacker
  - Run some monitoring on the streams / Try spoofing / High quality scripting

SL3:
  - Budget: 1M$
  - Small team of hacker

SL4:
  - Budget: 10M$
  - Large company or team hacker

SL5:
  - Budget: 1B$
  - Goverment / State

# Exercise 7

||Attack Vector|OC1|OC2|OC3|OC4|OC5|
|---|---|---|---|---|---|---|
|1|Exploiting vulnerabilities for which a patch exists|2|4|5|5|5|
|2|Exploiting reported but not (fully) patched vulnerabilities|2|3|4|5|5|
|3|Finding and exploiting individual zero-days|1|1|2|4|5|
|4|Social engineering for credentials|3|4|5|5|5|
|5|Password brute-forcing and cracking|1|1|2|3|3|
|6|Intentional ML supply chain compromise|1|1|3|4|5|
|7|Model extraction (through API)|1|1|1|2|2|
|8|Model distillation|1|1|1|2|3|
|9|Direct physical access to sensitive systems|1|1|2|2|3|
|10|Bribes and cooperation (with insiders)|1|1|2|4|5|

