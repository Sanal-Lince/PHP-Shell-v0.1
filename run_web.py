"""Start PHP2Scope's local-only web UI. Defaults to loopback and must not be exposed publicly."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("php2scope.webapp:app", host="127.0.0.1", port=8765, reload=False, access_log=False)
