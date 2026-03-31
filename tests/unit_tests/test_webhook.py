"""Unit tests for the webhook relay."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Patch env vars at module scope because main.py reads them
# at import time via os.getenv()
with patch.dict(
    "os.environ",
    {
        "LANGSMITH_API_KEY": "test-api-key",
        "AGENT_API_URL": "https://test.langgraph.app",
        "AGENT_ID": "test-agent-id",
        "GITHUB_WEBHOOK_SECRET": "test-secret",
    },
):
    from main import app, invoke_agent, validate_config, verify_signature


@pytest.fixture
def client() -> TestClient:
    """Create a test client for the FastAPI app."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def webhook_secret() -> str:
    """Return the test webhook secret."""
    return "test-secret"


def generate_signature(payload: bytes, secret: str) -> str:
    """Generate a valid GitHub webhook signature.

    Args:
        payload: The request body bytes.
        secret: The webhook secret.

    Returns:
        Signature string in format `sha256=<hex_digest>`.

    """
    signature = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={signature}"


class TestVerifySignature:
    """Tests for the `verify_signature` function."""

    def test_valid_signature(self) -> None:
        """Test that a valid signature is accepted."""
        payload = b"Hello, World!"
        secret = "test-secret"
        signature = generate_signature(payload, secret)

        assert verify_signature(payload, signature, secret) is True

    def test_invalid_signature(self) -> None:
        """Test that an invalid signature is rejected."""
        payload = b"Hello, World!"
        secret = "test-secret"
        wrong_signature = (
            "sha256=0000000000000000000000000000000000000000000000000000000000000000"
        )

        assert verify_signature(payload, wrong_signature, secret) is False

    def test_missing_signature(self) -> None:
        """Test that a missing signature is rejected."""
        payload = b"Hello, World!"
        secret = "test-secret"

        assert verify_signature(payload, None, secret) is False

    def test_malformed_signature_no_prefix(self) -> None:
        """Test that a signature without `sha256=` prefix is rejected."""
        payload = b"Hello, World!"
        secret = "test-secret"
        signature_without_prefix = hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()

        assert verify_signature(payload, signature_without_prefix, secret) is False

    def test_github_test_vector(self) -> None:
        """Test using GitHub's official test vector.

        From GitHub docs:

        - Secret: It's a Secret to Everybody
        - Payload: Hello, World!
        - Expected: sha256=757107ea0eb2509fc211221cce984b8a37570b6d...
        """
        payload = b"Hello, World!"
        secret = "It's a Secret to Everybody"
        expected_signature = (
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
        )

        assert verify_signature(payload, expected_signature, secret) is True

    def test_wrong_secret(self) -> None:
        """Test that wrong secret produces invalid signature."""
        payload = b"Hello, World!"
        correct_secret = "correct-secret"
        wrong_secret = "wrong-secret"
        signature = generate_signature(payload, correct_secret)

        assert verify_signature(payload, signature, wrong_secret) is False


class TestHealthEndpoint:
    """Tests for the `/health` endpoint."""

    def test_health_returns_ok(self, client: TestClient) -> None:
        """Test that health endpoint returns status ok."""
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestWebhookEndpoint:
    """Tests for the `/webhook` endpoint."""

    def test_invalid_signature_returns_401(
        self, client: TestClient, webhook_secret: str
    ) -> None:
        """Test that invalid signature returns `401 Unauthorized`."""
        payload = {"action": "opened", "number": 1}
        payload_bytes = json.dumps(payload).encode("utf-8")

        response = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=invalid",
                "X-GitHub-Event": "pull_request",
            },
        )

        assert response.status_code == 401

    def test_missing_signature_returns_401(self, client: TestClient) -> None:
        """Test that missing signature returns `401 Unauthorized`."""
        payload = {"action": "opened", "number": 1}
        payload_bytes = json.dumps(payload).encode("utf-8")

        response = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
            },
        )

        assert response.status_code == 401

    def test_non_pull_request_event_ignored(
        self, client: TestClient, webhook_secret: str
    ) -> None:
        """Test that non-`pull_request` events are ignored with `200`."""
        payload = {"action": "created"}
        payload_bytes = json.dumps(payload).encode("utf-8")
        signature = generate_signature(payload_bytes, webhook_secret)

        response = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "push",
            },
        )

        assert response.status_code == 200
        assert response.text == "Event ignored"

    def test_pull_request_non_opened_action_ignored(
        self, client: TestClient, webhook_secret: str
    ) -> None:
        """Test that `pull_request` events with non-`opened` action are ignored."""
        payload = {"action": "closed", "number": 1}
        payload_bytes = json.dumps(payload).encode("utf-8")
        signature = generate_signature(payload_bytes, webhook_secret)

        response = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "pull_request",
            },
        )

        assert response.status_code == 200
        assert response.text == "Event ignored"

    @patch("main.invoke_agent")
    def test_pull_request_opened_returns_202(
        self, mock_invoke: MagicMock, client: TestClient, webhook_secret: str
    ) -> None:
        """Test that `pull_request` opened event returns `202 Accepted`."""
        payload = {
            "action": "opened",
            "number": 42,
            "repository": {"full_name": "test/repo"},
            "pull_request": {"title": "Test PR"},
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        signature = generate_signature(payload_bytes, webhook_secret)

        response = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "pull_request",
            },
        )

        assert response.status_code == 202
        assert response.text == "Accepted"
        mock_invoke.assert_called_once_with(payload, "PR #42 in test/repo")

    def test_invalid_json_returns_400(
        self, client: TestClient, webhook_secret: str
    ) -> None:
        """Test that invalid JSON payload returns `400 Bad Request`."""
        payload_bytes = b"not valid json"
        signature = generate_signature(payload_bytes, webhook_secret)

        response = client.post(
            "/webhook",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "pull_request",
            },
        )

        assert response.status_code == 400


class TestValidateConfig:
    """Tests for the `validate_config` function."""

    def test_all_vars_set(self) -> None:
        """Test that no error is raised when all vars are set."""
        validate_config()

    def test_missing_single_var(self) -> None:
        """Test that a single missing var is reported."""
        with (
            patch("main.LANGSMITH_API_KEY", ""),
            pytest.raises(ValueError, match="LANGSMITH_API_KEY"),
        ):
            validate_config()

    def test_missing_multiple_vars(self) -> None:
        """Test that all missing vars are listed in the error message."""
        with (
            patch("main.LANGSMITH_API_KEY", ""),
            patch("main.AGENT_API_URL", ""),
        ):
            with pytest.raises(ValueError, match="LANGSMITH_API_KEY") as exc_info:
                validate_config()
            assert "AGENT_API_URL" in str(exc_info.value)

    def test_empty_string_treated_as_missing(self) -> None:
        """Test that empty string values are treated as missing."""
        with (
            patch("main.GITHUB_WEBHOOK_SECRET", ""),
            pytest.raises(ValueError, match="GITHUB_WEBHOOK_SECRET"),
        ):
            validate_config()


class TestInvokeAgent:
    """Tests for the `invoke_agent` function."""

    async def test_successful_invocation(self) -> None:
        """Test that agent invocation succeeds on first attempt."""
        mock_client = AsyncMock()
        mock_client.threads.create.return_value = {"thread_id": "test-thread"}

        with patch("main.get_client", return_value=mock_client):
            await invoke_agent({"action": "opened"}, "PR #1 in test/repo")

        mock_client.threads.create.assert_called_once()
        mock_client.runs.create.assert_called_once_with(
            "test-thread",
            "test-agent-id",
            input={
                "messages": [
                    {
                        "type": "human",
                        "content": json.dumps({"action": "opened"}),
                    }
                ]
            },
        )

    async def test_retries_on_transient_error(self) -> None:
        """Test that agent retries on network errors with correct delays."""
        mock_client = AsyncMock()
        mock_client.threads.create.side_effect = [
            OSError("connection refused"),
            {"thread_id": "test-thread"},
        ]

        with (
            patch("main.get_client", return_value=mock_client),
            patch("main.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            await invoke_agent({"action": "opened"}, "PR #1 in test/repo")

        assert mock_client.threads.create.call_count == 2
        mock_sleep.assert_called_once_with(1)

    async def test_raises_after_exhausted_retries(self) -> None:
        """Test that RuntimeError is raised after all retries fail."""
        mock_client = AsyncMock()
        mock_client.threads.create.side_effect = OSError("connection refused")

        with (
            patch("main.get_client", return_value=mock_client),
            patch("main.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(RuntimeError, match="after 3 attempts"),
        ):
            await invoke_agent({"action": "opened"}, "PR #1 in test/repo")

        assert mock_client.threads.create.call_count == 3

    async def test_does_not_retry_non_network_errors(self) -> None:
        """Test that non-network errors propagate immediately."""
        mock_client = AsyncMock()
        mock_client.threads.create.side_effect = KeyError("thread_id")

        with (
            patch("main.get_client", return_value=mock_client),
            pytest.raises(KeyError),
        ):
            await invoke_agent({"action": "opened"}, "PR #1 in test/repo")

        mock_client.threads.create.assert_called_once()
