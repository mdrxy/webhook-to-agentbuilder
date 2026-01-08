"""GitHub webhook relay to LangChain Agent Builder.

Receives GitHub webhook `POST` requests and forwards `pull_request 'opened'` events to a
LangChain Agent Builder agent.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import uvicorn
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, Response
from langgraph_sdk import get_client

load_dotenv()

LANGGRAPH_API_KEY = os.getenv("LANGGRAPH_API_KEY", "")
AGENT_API_URL = os.getenv("AGENT_API_URL", "")
AGENT_ID = os.getenv("AGENT_ID", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
PORT = int(os.getenv("PORT", "8000"))

MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def validate_config() -> None:
    """Validate that all required environment variables are set.

    Raises:
        ValueError: If any required environment variable is missing.

    """
    missing: list[str] = []

    if not LANGGRAPH_API_KEY:
        missing.append("LANGGRAPH_API_KEY")
    if not AGENT_API_URL:
        missing.append("AGENT_API_URL")
    if not AGENT_ID:
        missing.append("AGENT_ID")
    if not GITHUB_WEBHOOK_SECRET:
        missing.append("GITHUB_WEBHOOK_SECRET")

    if missing:
        msg = f"Missing required environment variables: {', '.join(missing)}"
        raise ValueError(msg)


def verify_signature(
    payload_body: bytes, signature_header: str | None, secret: str
) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        payload_body: Raw request body bytes (UTF-8 encoded).
        signature_header: Value of X-Hub-Signature-256 header.
        secret: GitHub webhook secret for HMAC computation.

    Returns:
        `True` if signature is valid, `False` otherwise.

    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    received_signature = signature_header[7:]  # Strip "sha256=" prefix
    return hmac.compare_digest(expected_signature, received_signature)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:  # noqa: ARG001
    """Application lifespan handler for startup and shutdown events.

    Args:
        app: FastAPI application instance.

    Yields:
        None after startup logging completes.

    """
    validate_config()
    logger.info("Webhook relay started")
    logger.info("Listening on port %d", PORT)
    logger.info("Endpoints: POST /webhook, GET /health")
    yield
    logger.info("Webhook relay shutting down")


app = FastAPI(lifespan=lifespan)


async def invoke_agent(payload: dict[str, Any], pr_info: str) -> None:
    """Invoke the LangGraph agent with the GitHub payload.

    Implements exponential backoff retry on failure.

    Args:
        payload: The GitHub webhook payload dictionary.
        pr_info: Human-readable PR identifier for logging.

    """
    client = get_client(
        url=AGENT_API_URL,
        api_key=LANGGRAPH_API_KEY,
        headers={
            "X-Auth-Scheme": "langsmith-api-key",
        },
    )

    payload_json = json.dumps(payload)

    for attempt in range(MAX_RETRIES):
        try:
            if attempt == 0:
                logger.info("Invoking agent for %s", pr_info)
            else:
                logger.info(
                    "Retrying agent for %s (attempt %d/%d)",
                    pr_info,
                    attempt + 1,
                    MAX_RETRIES,
                )

            input_data: dict[str, Any] = {
                "messages": [
                    {
                        "role": "human",
                        "content": payload_json,
                    }
                ]
            }

            result = await client.runs.wait(
                None,  # Threadless run
                AGENT_ID,
                input=input_data,
            )
        except Exception:
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_DELAYS[attempt]
                logger.warning(
                    "Agent invocation failed for %s. Retrying in %ds...",
                    pr_info,
                    delay,
                    exc_info=True,
                )
                await asyncio.sleep(delay)
            else:
                logger.exception(
                    "Agent invocation failed for %s after %d attempts",
                    pr_info,
                    MAX_RETRIES,
                )
        else:
            logger.info("Agent invocation successful for %s", pr_info)
            logger.info("Agent response: %s", result)
            return


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint for monitoring.

    Returns:
        Dictionary with status `'ok'`.

    """
    return {"status": "ok"}


@app.post("/webhook")
async def webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
) -> Response:
    """Receive and process GitHub webhook events.

    Validates the webhook signature, filters for `pull_request 'opened'` events, and
    forwards matching payloads to the LangGraph agent in a background task.

    Args:
        request: The incoming HTTP request.
        background_tasks: FastAPI background tasks handler.
        x_hub_signature_256: GitHub webhook signature header.
        x_github_event: GitHub event type header.

    Returns:
        Response with appropriate status code and message.

    Raises:
        HTTPException: If signature validation fails (401).

    """
    body = await request.body()

    if not verify_signature(body, x_hub_signature_256, GITHUB_WEBHOOK_SECRET):
        logger.warning("Invalid webhook signature received")
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload: dict[str, Any] = json.loads(body)
    except json.JSONDecodeError as e:
        msg = f"Invalid JSON payload: {e}"
        logger.warning(msg)
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from e

    if x_github_event != "pull_request":
        logger.info("Ignoring event type: %s", x_github_event)
        return Response(content="Event ignored", status_code=200)

    action = payload.get("action")
    if action != "opened":
        logger.info("Ignoring pull_request action: %s", action)
        return Response(content="Event ignored", status_code=200)

    pr_number = payload.get("number", "unknown")
    repo_name = payload.get("repository", {}).get("full_name", "unknown")
    pr_title = payload.get("pull_request", {}).get("title", "unknown")
    pr_info = f"PR #{pr_number} in {repo_name}"
    logger.info("Received pull_request opened: %s - %s", pr_info, pr_title)

    background_tasks.add_task(invoke_agent, payload, pr_info)

    return Response(content="Accepted", status_code=202)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, access_log=False)  # noqa: S104
