$ErrorActionPreference = "Stop"
uvicorn cloud_security_governance.main:app --app-dir src --reload

