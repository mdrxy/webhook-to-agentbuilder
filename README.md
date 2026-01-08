# webhook-to-agentbuilder

Lightweight webhook relay that receives GitHub webhook events and forwards them to a [LangSmith Agent Builder](https://docs.langchain.com/langsmith/agent-builder) agent.

## Features

- Validates GitHub webhook signatures (HMAC-SHA256)
- Filters for `pull_request` `opened` events only
- Exponential backoff retry on agent failures

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description |
|----------|-------------|
| `LANGGRAPH_API_KEY` | LangSmith Personal Access Token |
| `AGENT_API_URL` | Agent Builder deployment URL |
| `AGENT_ID` | Agent UUID from Agent Builder settings |
| `GITHUB_WEBHOOK_SECRET` | Secret configured in GitHub webhook settings |
| `PORT` | Server port (default: 8000) |

## Local Development

```bash
# Install dependencies
make install-dev

# Run development server
make dev

# Run tests
make test

# Lint and format
make lint
make format
```

## Docker Deployment

```bash
# Build and run
make docker-up

# Stop
make docker-down
```

## GitHub Webhook Setup

1. Go to your repo's Settings > Webhooks > Add webhook
2. Set Payload URL to `https://your-domain.com/webhook`
3. Set Content type to `application/json`
4. Set Secret to match your `GITHUB_WEBHOOK_SECRET`
5. Select "Let me select individual events" > check "Pull requests"

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook` | POST | Receives GitHub webhooks |
| `/health` | GET | Health check (returns `{"status": "ok"}`) |
