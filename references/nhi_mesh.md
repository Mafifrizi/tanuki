# Non-Human Identity (NHI) & Workload Federation (2026-2030 Architecture)

Strategic guide to evaluating ephemeral machine identities, autonomous AI agent credentials, and hybrid federation pathways operating on Linux substrates.

## 1. The NHI Paradigm Shift
By 2026-2030, enterprise identities are dominated by non-human actors:
* Workload Identities (Kubernetes pods, cloud functions, microservices)
* Ephemeral service tokens and certificates (SPIFFE/SPIRE SVIDs)
* Autonomous AI agent runtimes interacting through Model Context Protocol (MCP) and dynamic token exchange

## 2. Linux Token Discovery Paths

| Artifact Type | Default System Path | Triage Mechanism |
| :--- | :--- | :--- |
| **Kubernetes Projected Token** | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Extract JWT; verify issuer and audience against OIDC discovery endpoint. |
| **Cloud IMDSv2 Token (AWS)** | `http://169.254.169.254/latest/api/token` | Request session token via `PUT`; query IAM role credentials. |
| **Azure Managed Identity** | `http://169.254.169.254/metadata/identity/oauth2/token` | Query with `Metadata: true` header to obtain Entra ID bearer tokens. |
| **SPIFFE Workload Socket** | `/tmp/spire-agent/public/api.sock` or `unix:///run/spire/sockets/agent.sock` | Fetch X.509 SVID using standard SPIFFE Workload API gRPC call. |

## 3. RFC 8693 OAuth 2.0 Token Exchange
In modern hybrid enterprises, a Linux workload token (e.g., GitHub Actions OIDC or Kubernetes token) is exchanged for a cloud service principal or Entra ID access token:

```text
[ Linux Workload Token (JWT) ] 
          │
          ▼  (RFC 8693 grant_type=urn:ietf:params:oauth:grant-type:token-exchange)
[ STS / Entra ID Federation ]
          │
          ▼  (Cloud Kerberos Trust / IAKerb)
[ On-Premises Active Directory Domain Controller ]
```

Assessors must evaluate:
1. Are subject claims (`sub`) strictly scoped or overly permissive (wildcards in repo/namespace)?
2. Does the federated identity possess privilege escalation paths in both cloud IAM and down-level directory trees?
