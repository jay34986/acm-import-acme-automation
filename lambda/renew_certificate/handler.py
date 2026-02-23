"""
Lambda function that renews TLS certificates via ACME (Let's Encrypt)
and imports them into AWS Certificate Manager (ACM).

Environment variables:
  ACME_DIRECTORY_URL      - ACME directory URL (Let's Encrypt production or staging)
  ACME_ACCOUNT_SECRET_ARN - Secrets Manager ARN for the ACME account private key
  CERT_SECRET_ARN         - Secrets Manager ARN to store the issued certificate data
  CHALLENGE_BUCKET        - S3 bucket name for HTTP-01 challenge tokens
  DOMAIN                  - Domain / IP address to issue the certificate for
  CERTIFICATE_ARN         - (optional) Existing ACM certificate ARN to update
  AWS_DEFAULT_REGION      - AWS region (e.g. ap-northeast-1)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Final, Protocol, cast

import boto3
import josepy as jose
from acme import challenges, client, errors, messages
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SecretsManagerClient(Protocol):
    def get_secret_value(self, *, SecretId: str) -> Mapping[str, object]: ...

    def put_secret_value(
        self, *, SecretId: str, SecretString: str
    ) -> Mapping[str, object]: ...


class S3Client(Protocol):
    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ContentType: str,
    ) -> Mapping[str, object]: ...

    def delete_object(self, *, Bucket: str, Key: str) -> Mapping[str, object]: ...


class AcmClient(Protocol):
    def import_certificate(
        self,
        *,
        Certificate: bytes,
        PrivateKey: bytes,
        CertificateChain: bytes,
        CertificateArn: str | None = None,
    ) -> Mapping[str, object]: ...


class AcmeClientWithProfile(Protocol):
    def new_order(
        self,
        csr_pem: bytes,
        *,
        profile: str,
    ) -> messages.OrderResource: ...


# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
ACME_DIRECTORY_URL: str = os.environ["ACME_DIRECTORY_URL"]
ACME_ACCOUNT_SECRET_ARN: str = os.environ["ACME_ACCOUNT_SECRET_ARN"]
CERT_SECRET_ARN: str = os.environ["CERT_SECRET_ARN"]
CHALLENGE_BUCKET: str = os.environ["CHALLENGE_BUCKET"]
DOMAIN: str = os.environ["DOMAIN"]
CERTIFICATE_ARN: str | None = os.environ.get("CERTIFICATE_ARN")
AWS_REGION: str = os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1")

# ACME RSA key size for account and certificate keys
ACCOUNT_KEY_BITS: Final[int] = 2048
CERT_KEY_BITS: Final[int] = 2048

# ---------------------------------------------------------------------------
# AWS clients (module-level for Lambda container reuse)
# ---------------------------------------------------------------------------
sm_client: SecretsManagerClient = cast(
    SecretsManagerClient,
    boto3.client("secretsmanager", region_name=AWS_REGION),
)
s3_client: S3Client = cast(S3Client, boto3.client("s3", region_name=AWS_REGION))
acm_client: AcmClient = cast(AcmClient, boto3.client("acm", region_name=AWS_REGION))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_or_create_account_key() -> jose.JWKRSA:
    """Load the ACME account RSA key from Secrets Manager, creating it on first run."""
    secret = sm_client.get_secret_value(SecretId=ACME_ACCOUNT_SECRET_ARN)
    secret_string = secret.get("SecretString")
    if not isinstance(secret_string, str):
        raise RuntimeError("SecretString is missing or invalid for ACME account secret")

    parsed_data = json.loads(secret_string)
    if not isinstance(parsed_data, dict):
        raise RuntimeError("ACME account secret payload must be a JSON object")
    data: dict[str, object] = dict(parsed_data)

    pem_value = data.get("key", "")
    if not isinstance(pem_value, str):
        raise RuntimeError("The 'key' field in ACME account secret must be a string")
    pem = pem_value

    if pem:
        logger.info("Loaded existing ACME account key from Secrets Manager")
        private_key = serialization.load_pem_private_key(
            pem.encode(), password=None, backend=default_backend()
        )
        return jose.JWKRSA(key=private_key)

    # Generate a new RSA key and persist it
    logger.info("No ACME account key found – generating a new one")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=ACCOUNT_KEY_BITS,
        backend=default_backend(),
    )
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    data["key"] = pem_bytes.decode()
    sm_client.put_secret_value(
        SecretId=ACME_ACCOUNT_SECRET_ARN,
        SecretString=json.dumps(data),
    )
    return jose.JWKRSA(key=private_key)


def _generate_cert_key() -> rsa.RSAPrivateKey:
    """Generate a fresh RSA private key for the new certificate."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=CERT_KEY_BITS,
        backend=default_backend(),
    )


def _generate_csr(domain: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """Return a PEM-encoded CSR for *domain*."""
    san_name: x509.GeneralName
    subject_name: x509.Name
    try:
        parsed_ip = ipaddress.ip_address(domain)
        san_name = x509.IPAddress(parsed_ip)
        subject_name = x509.Name([])
    except ValueError:
        san_name = x509.DNSName(domain)
        subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject_name)
        .add_extension(
            x509.SubjectAlternativeName([san_name]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _resolve_acme_profile(identifier: str) -> str | None:
    """Resolve ACME profile based on identifier type.

    Let's Encrypt の IP 証明書は shortlived プロファイル必須。
    DNS は既存互換のためデフォルトプロファイル(None)を利用する。
    """
    try:
        ipaddress.ip_address(identifier)
        return "shortlived"
    except ValueError:
        return None


def _register_or_find_account(acme_client: client.ClientV2) -> None:
    """Register a new ACME account or confirm an existing one."""
    try:
        reg = messages.NewRegistration.from_data(
            email=None, terms_of_service_agreed=True
        )
        acme_client.new_account(reg)
        logger.info("Registered new ACME account")
    except errors.ConflictError as exc:
        account_url = exc.location if isinstance(exc.location, str) else ""

        if account_url == "" or account_url == "UNKNOWN-LOCATION":
            existing_only = messages.NewRegistration.from_data(
                email=None,
                terms_of_service_agreed=True,
                only_return_existing=True,
            )
            acme_client.new_account(existing_only)
            logger.info(
                "ACME account already exists (resolved via only_return_existing)"
            )
            return

        existing_registration = messages.RegistrationResource(
            body=messages.Registration.from_data(),
            uri=account_url,
            new_authzr_uri=None,
            terms_of_service=None,
        )
        acme_client.query_registration(existing_registration)
        logger.info("ACME account already exists: %s", account_url)


def _upload_challenge_token(token_path: str, key_authorisation: str) -> None:
    """Upload the HTTP-01 challenge token to S3."""
    s3_key = f".well-known/acme-challenge/{token_path}"
    s3_client.put_object(
        Bucket=CHALLENGE_BUCKET,
        Key=s3_key,
        Body=key_authorisation.encode(),
        ContentType="text/plain",
    )
    logger.info("Uploaded challenge token to s3://%s/%s", CHALLENGE_BUCKET, s3_key)


def _delete_challenge_token(token_path: str) -> None:
    """Clean up the HTTP-01 challenge token from S3."""
    s3_key = f".well-known/acme-challenge/{token_path}"
    try:
        s3_client.delete_object(Bucket=CHALLENGE_BUCKET, Key=s3_key)
        logger.info("Deleted challenge token s3://%s/%s", CHALLENGE_BUCKET, s3_key)
    except ClientError as exc:
        logger.warning("Failed to delete challenge token: %s", exc)


def _verify_http_challenge_reachability(
    token_path: str, key_authorisation: str
) -> None:
    """Verify that the HTTP-01 token is publicly reachable before answering ACME challenge."""
    challenge_url = f"http://{DOMAIN}/.well-known/acme-challenge/{token_path}"
    deadline = time.monotonic() + 30.0
    last_error = ""

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(challenge_url, timeout=5) as response:
                status_code = response.getcode()
                body_bytes = response.read()

            body = body_bytes.decode().strip()
            expected = key_authorisation.strip()

            if status_code == 200 and body == expected:
                logger.info("Challenge URL is reachable: %s", challenge_url)
                return

            last_error = (
                f"Unexpected challenge response (status={status_code}, "
                f"body_matches={body == expected})"
            )
        except urllib.error.URLError as exc:
            last_error = str(exc)

        time.sleep(2)

    raise RuntimeError(
        "HTTP-01 precheck failed: challenge URL is not reachable from public network. "
        f"url={challenge_url}, last_error={last_error}"
    )


def _store_cert_in_secrets_manager(
    certificate_pem: str,
    private_key_pem: str,
    chain_pem: str,
) -> None:
    """Persist certificate data to Secrets Manager."""
    payload = json.dumps(
        {
            "certificate": certificate_pem,
            "privateKey": private_key_pem,
            "chain": chain_pem,
        }
    )
    sm_client.put_secret_value(
        SecretId=CERT_SECRET_ARN,
        SecretString=payload,
    )
    logger.info("Certificate stored in Secrets Manager: %s", CERT_SECRET_ARN)


def _import_to_acm(
    certificate_pem: str,
    private_key_pem: str,
    chain_pem: str,
) -> str:
    """Import (or re-import) the certificate into ACM. Returns the certificate ARN."""
    kwargs: dict[str, bytes | str] = {
        "Certificate": certificate_pem.encode(),
        "PrivateKey": private_key_pem.encode(),
        "CertificateChain": chain_pem.encode(),
    }

    if CERTIFICATE_ARN:
        kwargs["CertificateArn"] = CERTIFICATE_ARN
        logger.info("Re-importing certificate to ACM: %s", CERTIFICATE_ARN)
    else:
        logger.info("Importing new certificate to ACM")

    response = acm_client.import_certificate(**kwargs)  # type: ignore[arg-type]

    arn_value = response.get("CertificateArn")
    if not isinstance(arn_value, str):
        raise RuntimeError("ACM import response did not include a valid CertificateArn")
    logger.info("ACM certificate ARN: %s", arn_value)
    return arn_value


# ---------------------------------------------------------------------------
# Orchestration helpers
# ---------------------------------------------------------------------------


def _build_acme_client(
    account_key: jose.JWKRSA,
) -> client.ClientV2:
    """Build and register an ACME client with the configured directory."""
    net = client.ClientNetwork(account_key, user_agent="acm-import-acme-automation/1.0")
    directory_json = net.get(ACME_DIRECTORY_URL).json()
    directory = messages.Directory.from_json(directory_json)
    acme = client.ClientV2(directory, net)
    _register_or_find_account(acme)
    return acme


def _create_order(
    acme: client.ClientV2,
    csr_pem: bytes,
    acme_profile: str | None,
) -> messages.OrderResource:
    """Create a new ACME certificate order, optionally with a profile."""
    if acme_profile is None:
        order = acme.new_order(csr_pem)
    else:
        profiled = cast(AcmeClientWithProfile, acme)
        order = profiled.new_order(csr_pem, profile=acme_profile)
    logger.info("Created ACME order: %s", order.uri)
    return order


def _perform_http01_challenges(
    acme: client.ClientV2,
    order: messages.OrderResource,
    account_key: jose.JWKRSA,
) -> messages.OrderResource:
    """Upload HTTP-01 tokens, verify reachability, answer challenges, and finalise."""
    challenge_tokens: list[str] = []
    try:
        for auth in order.authorizations:
            domain_name = auth.body.identifier.value
            logger.info("Processing authorisation for: %s", domain_name)

            http01_chall = None
            for chall_body in auth.body.challenges:
                if isinstance(chall_body.chall, challenges.HTTP01):
                    http01_chall = chall_body
                    break

            if http01_chall is None:
                raise RuntimeError(f"No HTTP-01 challenge found for {domain_name}")

            if hasattr(http01_chall.chall, "encode"):
                token_path = http01_chall.chall.encode("token")
            else:
                token_path = http01_chall.chall.encode_token()
            key_auth = http01_chall.chall.key_authorization(account_key)

            _upload_challenge_token(token_path, key_auth)
            challenge_tokens.append(token_path)
            _verify_http_challenge_reachability(token_path, key_auth)

            acme.answer_challenge(
                http01_chall, http01_chall.chall.response(account_key)
            )
            logger.info("Challenge answered for %s", domain_name)

        logger.info("Finalising ACME order…")
        return acme.poll_and_finalize(order)

    finally:
        for token_path in challenge_tokens:
            _delete_challenge_token(token_path)


def _process_issued_certificate(
    order: messages.OrderResource,
    cert_private_key: rsa.RSAPrivateKey,
) -> str:
    """Extract cert from finalised order, store in Secrets Manager, import to ACM.

    Returns the ACM certificate ARN.
    """
    fullchain_pem = order.fullchain_pem
    if not fullchain_pem:
        raise RuntimeError("No certificate returned by ACME server")

    pem_blocks = _split_pem(fullchain_pem)
    certificate_pem = pem_blocks[0]
    chain_pem = "".join(pem_blocks[1:]) if len(pem_blocks) > 1 else ""

    private_key_pem = cert_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    _store_cert_in_secrets_manager(certificate_pem, private_key_pem, chain_pem)
    return _import_to_acm(certificate_pem, private_key_pem, chain_pem)


def _renew_certificate() -> str:
    """Execute the full ACME certificate renewal workflow.

    Returns the ACM certificate ARN.
    """
    account_key = _load_or_create_account_key()
    acme = _build_acme_client(account_key)

    acme_profile = _resolve_acme_profile(DOMAIN)
    if acme_profile is not None:
        logger.info("Using ACME profile '%s' for identifier '%s'", acme_profile, DOMAIN)

    cert_private_key = _generate_cert_key()
    csr_pem = _generate_csr(DOMAIN, cert_private_key)

    order = _create_order(acme, csr_pem, acme_profile)
    finalised_order = _perform_http01_challenges(acme, order, account_key)

    return _process_issued_certificate(finalised_order, cert_private_key)


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------


def lambda_handler(
    event: dict[str, object],  # noqa: ARG001
    context: object,  # noqa: ARG001
) -> dict[str, object]:
    """Renew a TLS certificate via ACME and import it to ACM.

    Parameters
    ----------
    event:
        Lambda event payload (not used; the function is triggered manually or
        on a schedule without meaningful input).
    context:
        Lambda runtime context (not used).

    Returns
    -------
    dict
        A dict with ``statusCode`` (200 on success, 500 on failure) and a
        JSON-encoded ``body`` containing ``message``, ``domain``, and
        ``certificateArn`` (on success) or ``error`` (on failure).
    """
    logger.info("Starting certificate renewal for domain: %s", DOMAIN)

    try:
        acm_arn = _renew_certificate()
        logger.info("Certificate renewal completed successfully")
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Certificate renewed successfully",
                    "domain": DOMAIN,
                    "certificateArn": acm_arn,
                }
            ),
        }
    except Exception as exc:
        logger.exception("Certificate renewal failed: %s", exc)
        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": "Certificate renewal failed",
                    "error": str(exc),
                }
            ),
        }


def _split_pem(pem_data: str) -> list[str]:
    """Split a PEM string containing multiple certificates into individual PEM strings."""
    blocks: list[str] = []
    current: list[str] = []
    for line in pem_data.splitlines(keepends=True):
        current.append(line)
        if "-----END CERTIFICATE-----" in line:
            blocks.append("".join(current))
            current = []
    return blocks
