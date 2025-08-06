# Exercise 1:

inference service -> API gateway -> user

- S: Spoofing: stealing the credentials (e.g. by phishing) to access a proprietary model
- T: Tampering: MITM -- changes response from the server in order to spread misinformation
- R: Repudiation: an employee accesses the model weights, but the company does not maintain logs of who has access to model weights at a given time
- I: Information Disclosure: API leaking information to the public inernet, such that past chat conversations are accessible through a web search (e.g. the recent OpenAI example)
- D: Denial of Service: standard DOS or DDoS -- overwhelming the API by sending thousands of requests. Uploading massive files or, in the LLM case, requests that fill the context window
- E: Elevation of Privelege: could be done by social engineering on the inside of the company (e.g. convincing your manager to grant you access to some folder even though you don't need it)

# Exercise 2:
## Data assets
- customer requests and responses
- customer identity
- frontier model weights
- code and configuration for evaluation experiment jobs - experiment results and details
- Intellectual Property
- small model weights should be accessible by researchers, but not the public

## System/Infrastructure Assets
- the inference cluster
- the training cluster

## Service assets
- the service that exposes the frontier LLM to customers (API + frontend)
- service that exposes the frontier LLM to inside researchers
- UI for examining experiment results
- job orchestration service
- inference service
- experiment tracking service

## People/access assets
- user accounts, credentials
- API keys

## Reputation/business assets
- litigation losses
- public trust/perception/reputation
- competitive advantage

# Exercise 3t

# Exercise 4
| Data Flow / Asset | Category | Threat | Priority | Mitigations |
| :---- | :---- | :---- | :---- | :---- |
| External Collaborator \-\> job orchestration | Spoofing | The collaborator submits a job to the job orchestration service which steals the credentials of the incoming API calls.  | Likelihood: high Impact: high | HTTPS Escape submitted code Isolation of submitted jobs |
|  | Tampering | The cluster is misconfigured so that the collaborator can view the experimental results of all other participants (without privilege escalation) and modify/delete them | Likelihood: High Impact: Medium | Per-user permissions to read/write data in a particular folder. When querying a database, the user ID of the retrieved record must match the user ID of the request. |
|  | Repudiation | Sharing API keys by third-party organisations/external collaborators | Likelihood: very high Impact: Low-Medium | Don’t share API keys |
|  | Information Disclosure | After spoofing, the collaborator acquires the researchers credentials and uses them to access frontier model weights. | Likelihood: High (for OC4 and above) Impact: critical | Separate credentials for orchestration (Kubeflow) and model access (inference service).  Sharded keys for model access. |
|  | Denial of Service | Upload big files or spam requests to the job scheduler | Likelihood: Low Impact: Low | Rate limiting |
|  | Elevation of Privilege | Injection attack on the underlying OS through the submitted job. | Likelihood: Medium Impact: Critical | Escape all submitted code and data. |


