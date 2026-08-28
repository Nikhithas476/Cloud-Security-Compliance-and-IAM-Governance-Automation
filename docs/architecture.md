# Day 1 Architecture

The initial service is a small FastAPI application under `src/cloud_security_governance`.
Configuration is loaded from safe YAML defaults and overridden by environment variables. Logs are
emitted as JSON, and expected domain failures share a typed exception hierarchy. AWS Lambda and
Azure Functions contain health-only placeholders. Provider clients and scanning workflows will be
added in later phases.

No cloud API calls or scanning logic are present in this foundation.

