"""GitHub webhook relay to LangSmith Fleet.

Receives GitHub webhook `POST` requests and forwards `pull_request 'opened'`
events to a LangSmith Fleet agent.
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

LANGSMITH_API_KEY = os.getenv("LANGSMITH_API_KEY", "")
AGENT_API_URL = os.getenv("AGENT_API_URL", "")
AGENT_ID = os.getenv("AGENT_ID", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
PORT = int(os.getenv("PORT", "8000"))

MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]  # seconds
AGENT_TIMEOUT = 7200  # seconds to wait for agent response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def validate_config() -> None:
    """Validate that all required environment variables are set and non-empty.

    Raises:
        ValueError: If any required environment variable is missing.

    """
    missing: list[str] = []

    if not LANGSMITH_API_KEY:
        missing.append("LANGSMITH_API_KEY")
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
        payload_body: Raw request body bytes.
        signature_header: Value of X-Hub-Signature-256 header.
        secret: GitHub webhook secret for HMAC computation.

    Returns:
        `True` if signature is valid, `False` otherwise.

    """
    if not signature_header:
        logger.warning("Webhook signature header is missing")
        return False

    if not signature_header.startswith("sha256="):
        logger.warning(
            "Webhook signature has unexpected format (expected sha256= prefix)"
        )
        return False

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    received_signature = signature_header.removeprefix("sha256=")
    if not hmac.compare_digest(expected_signature, received_signature):
        logger.warning("Webhook signature mismatch (HMAC comparison failed)")
        return False

    return True


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


async def invoke_agent(
    payload: dict[str, Any],
    pr_info: str,
    *,
    wait_for_response: bool = False,
) -> list[dict[str, Any]] | dict[str, Any] | None:
    """Invoke the LangGraph agent with the GitHub payload.

    Retries on transient network errors with fixed backoff delays. All failures
    are logged; a `RuntimeError` is raised after retries are exhausted so that
    the background task runner surfaces the failure.

    Args:
        payload: The GitHub webhook payload dictionary.
        pr_info: Human-readable PR identifier for logging.
        wait_for_response: If `True`, block until the agent finishes and return
            its final state.

            If `False`, fire-and-forget.

    Returns:
        The agent's final state (dict or list of dicts) when
        `wait_for_response` is `True`, or `None` when it is `False`.

    Raises:
        RuntimeError: If agent invocation fails after all retry attempts.

    """
    client = get_client(
        url=AGENT_API_URL,
        api_key=LANGSMITH_API_KEY,
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
                        "type": "human",
                        "content": payload_json,
                    }
                ]
            }

            thread = await client.threads.create()
            thread_id = thread["thread_id"]

            if wait_for_response:
                result = await asyncio.wait_for(
                    client.runs.wait(
                        thread_id,
                        AGENT_ID,
                        input=input_data,
                    ),
                    timeout=AGENT_TIMEOUT,
                )
                logger.info("Agent response for %s: %s", pr_info, result)
                return result

            await client.runs.create(
                thread_id,
                AGENT_ID,
                input=input_data,
            )
            logger.info("Agent invocation successful for %s", pr_info)
            return None
        except TimeoutError as exc:
            logger.exception("Agent timed out after %ds for %s", AGENT_TIMEOUT, pr_info)
            msg = f"Agent timed out after {AGENT_TIMEOUT}s for {pr_info}"
            raise RuntimeError(msg) from exc
        except OSError as exc:
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
                msg = (
                    f"Agent invocation failed for {pr_info} "
                    f"after {MAX_RETRIES} attempts"
                )
                logger.exception(msg)
                raise RuntimeError(msg) from exc

    return None


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
        HTTPException: If signature validation fails (401) or the request body
            contains invalid JSON (400).

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
        logger.debug("Ignoring event type: %s", x_github_event)
        return Response(content="Event ignored", status_code=200)

    action = payload.get("action")
    if action != "opened":
        logger.debug("Ignoring pull_request action: %s", action)
        return Response(content="Event ignored", status_code=200)

    pr_number = payload.get("number", "unknown")
    repository = payload.get("repository")
    repo_name = (
        repository.get("full_name", "unknown")
        if isinstance(repository, dict)
        else "unknown"
    )
    pull_request = payload.get("pull_request")
    pr_title = (
        pull_request.get("title", "unknown")
        if isinstance(pull_request, dict)
        else "unknown"
    )
    pr_info = f"PR #{pr_number} in {repo_name}"
    logger.info("Received pull_request opened: %s - %s", pr_info, pr_title)

    background_tasks.add_task(invoke_agent, payload, pr_info)

    return Response(content="Accepted", status_code=202)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, access_log=False)  # noqa: S104
