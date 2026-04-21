# Azure Web App Deployment Guide

This project is a Python FastAPI WebSocket API with one `/ws` endpoint, one optional `/chat` HTTP endpoint, and `/health` for health checks. The LangGraph agent uses DeepSeek Chat through an OpenAI-compatible client.

## Required environment variables

Set these in Azure App Service Configuration or in your hosting environment:

- `DEEPSEEK_API_KEY`
- `DEEPSEEK_MODEL` optional, defaults to `deepseek-chat`
- `DEEPSEEK_BASE_URL` optional, defaults to `https://api.deepseek.com`
- `DEEPSEEK_MAX_TOKENS` optional, defaults to `8000`
- `VIRUS_API_KEY`
- `VIRUS_BASE_URL` optional, defaults to `https://www.virustotal.com/api/v3`
- `NVD_API_KEY` optional, but recommended for NVD rate limits
- `ALLOWED_ORIGINS` optional, comma-separated origins or `*`

## GitHub repository structure

Keep these files at the root of the GitHub repository:

```text
src/main.py
src/agent.py
src/tools.py
src/__init__.py
requirements.txt
guide.md
```

## Azure Portal deployment steps

1. Push this code to GitHub.
2. Open the Azure Portal.
3. Search for `App Services`.
4. Select `Create`.
5. Choose your subscription and resource group.
6. Enter an app name.
7. Set `Publish` to `Code`.
8. Set `Runtime stack` to `Python`.
9. Choose Python 3.12 if available in your region.
10. Select Linux as the operating system.
11. Choose the region and pricing plan.
12. Create the Web App.
13. Open the created Web App.
14. Go to `Settings` then `Environment variables`.
15. Add the required environment variables listed above.
16. Go to `Settings` then `Configuration` then `General settings`.
17. Set the startup command to:

```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

18. Save the configuration.
19. Go to `Deployment` then `Deployment Center`.
20. Select `GitHub` as the source.
21. Sign in to GitHub if prompted.
22. Select your organization, repository, and branch.
23. Choose GitHub Actions if Azure asks for a build provider.
24. Save the deployment settings.
25. Wait for the first deployment to complete.
26. Open `https://<your-app-name>.azurewebsites.net/health` and confirm it returns:

```json
{"status":"ok"}
```

## WebSocket usage

Connect to:

```text
wss://<your-app-name>.azurewebsites.net/ws
```

Send plain text:

```text
CVE-2024-3094
```

Or send JSON:

```json
{"message":"check 8.8.8.8","session_id":"user-123"}
```

The server responds with JSON:

```json
{
  "type": "response",
  "session_id": "user-123",
  "response": "..."
}
```

## Optional HTTP usage

You can also call:

```text
POST https://<your-app-name>.azurewebsites.net/chat
```

With body:

```json
{"message":"check example.com","session_id":"user-123"}
```

## Notes

- Azure OpenAI is not used.
- DeepSeek Chat is used as the LLM via `DEEPSEEK_API_KEY`.
- The old log-analysis tool is not included.
- The agent only uses CVE, IP, domain, URL, and hash tools.
- VirusTotal is used for IP, domain, URL, and hash intelligence.
- NVD is used for CVE intelligence.
- If Azure shows startup failures, check `Log stream` under `Monitoring` in the Azure Portal.
