"""Utilities for extracting client credentials from requests."""

import base64
from typing import Tuple

from starlette.requests import Request

from mcp.shared.auth import OAuthClientInformationFull


class ClientCredentialError(Exception):
    """Error extracting client credentials."""
    def __init__(self, error: str, error_description: str):
        self.error = error
        self.error_description = error_description
        super().__init__(error_description)


def extract_client_credentials(
    request: Request,
    client: OAuthClientInformationFull,
    client_id_from_body: str,
    client_secret_from_body: str | None = None,
) -> Tuple[str, str | None]:
    """
    Extract client credentials based on the client's registered authentication method.
    
    Args:
        request: The HTTP request
        client: The client information with registered auth method
        client_id_from_body: The client_id from the request body
        client_secret_from_body: The client_secret from the request body (if present)
    
    Returns:
        Tuple of (client_id, client_secret)
    
    Raises:
        ClientCredentialError: If credentials are missing or invalid
    """
    client_id = client_id_from_body
    client_secret = None
    
    if client.token_endpoint_auth_method == "client_secret_basic":
        # Must use Basic auth header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            raise ClientCredentialError(
                "invalid_client",
                "Client must use Basic authentication"
            )
        try:
            # Decode Basic auth header
            encoded_credentials = auth_header[6:]  # Remove "Basic " prefix
            decoded = base64.b64decode(encoded_credentials).decode("utf-8")
            if ":" not in decoded:
                raise ValueError("Invalid Basic auth format")
            basic_client_id, client_secret = decoded.split(":", 1)
            # Verify client_id matches
            if basic_client_id != client_id:
                raise ClientCredentialError(
                    "invalid_client",
                    "Client ID mismatch"
                )
        except ClientCredentialError:
            raise
        except Exception:
            raise ClientCredentialError(
                "invalid_client",
                "Invalid Basic authentication header"
            )
    
    elif client.token_endpoint_auth_method == "client_secret_post":
        # Must use POST body
        client_secret = client_secret_from_body
        if client.client_secret and not client_secret:
            raise ClientCredentialError(
                "invalid_client",
                "Client secret required in request body"
            )
    
    elif client.token_endpoint_auth_method == "none":
        # Public client, no secret expected
        client_secret = None
    
    return client_id, client_secret