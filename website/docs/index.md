---
layout: home

hero:
  name: Kloak Documentation
  tagline: Secure your Kubernetes secrets with zero code changes
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/quick-start
    - theme: alt
      text: View on GitHub
      link: https://github.com/getkloak/kloak

features:
  - title: Zero Code Changes
    details: Applications use hashed shadow values that get transparently rewritten at runtime. No SDK, no sidecar, no code modifications required.
  - title: eBPF Powered
    details: In-kernel uprobes intercept TLS writes and replace placeholders with real secret values before transmission, with minimal overhead.
  - title: Host Filtering
    details: Restrict which destination hosts each secret can be sent to, preventing accidental or malicious exfiltration of sensitive data.
---
