import json
import time
import logging
import urllib.request
import os
import jwt
import boto3
from jwt.algorithms import RSAAlgorithm

# Structured logger configuration
SERVICE_NAME = os.environ.get("SERVICE_NAME", "authorizer")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logger = logging.getLogger(SERVICE_NAME)
if not logger.handlers:
    handler = logging.StreamHandler()

    class JsonFormatter(logging.Formatter):
        def format(self, record):
            base = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
                "level": record.levelname,
                "service": SERVICE_NAME,
                "message": record.getMessage(),
            }
            # include simple extras
            extras = {k: v for k, v in record.__dict__.items()
                      if k not in ("name", "msg", "args", "levelname", "levelno", "pathname",
                                   "filename", "module", "exc_info", "exc_text", "stack_info",
                                   "lineno", "funcName", "created", "msecs", "relativeCreated",
                                   "thread", "threadName", "processName", "process")}
            if extras:
                base.update(extras)
            return json.dumps(base)

    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)

logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))


def enrich(extra: dict = None, request_id: str = None) -> dict:
    base = {"service": SERVICE_NAME}
    if request_id:
        base["requestId"] = request_id
    if extra:
        base.update(extra)
    return base

ssm = boto3.client("ssm")

# =========================
# CACHE
# =========================
CONFIG_CACHE = {"loaded": False}
JWKS_CACHE = {"keys": None, "ts": 0}
POLICY_CACHE = {}

JWKS_TTL = 3600
POLICY_TTL = 300  # 5 min per user

# =========================
# PERMISSION MATRIX (ENTERPRISE CORE)
# =========================
PERMISSIONS = {
    "admin": {
        "allow": ["*"]
    },
    "doctor_admin": {
        "allow": ["GET /doctors", "POST /doctors", "PUT /doctors/*", "DELETE /doctors/*"]
    },
    "doctor_readonly": {
        "allow": ["GET /doctors", "GET /doctors/*"]
    }
}

# =========================
# CONFIG LOADER (SSM)
# =========================
def load_config():
    if CONFIG_CACHE["loaded"]:
        logger.debug("Config cache hit")
        return CONFIG_CACHE

    logger.info("Loading configuration from SSM")
    user_pool_id = ssm.get_parameter(
        Name=os.environ["COGNITO_USER_POOL_ID_SSM"],
        WithDecryption=False
    )["Parameter"]["Value"]

    client_id = ssm.get_parameter(
        Name=os.environ["COGNITO_CLIENT_ID_SSM"],
        WithDecryption=False
    )["Parameter"]["Value"]

    region = os.environ.get("AWS_REGION", "us-west-2")

    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    jwks_url = f"{issuer}/.well-known/jwks.json"

    CONFIG_CACHE.update({
        "loaded": True,
        "user_pool_id": user_pool_id,
        "client_id": client_id,
        "region": region,
        "issuer": issuer,
        "jwks_url": jwks_url
    })

    logger.info("Configuration loaded", extra=enrich({"issuer": issuer, "client_id": client_id}))
    return CONFIG_CACHE

# =========================
# JWKS CACHE
# =========================
def get_jwks(cfg):
    now = time.time()

    if JWKS_CACHE["keys"] and now - JWKS_CACHE["ts"] < JWKS_TTL:
        logger.debug("JWKS cache hit", extra=enrich({"cached": True}))
        return JWKS_CACHE["keys"]

    logger.info("Fetching JWKS", extra=enrich({"jwks_url": cfg.get("jwks_url")}))
    try:
        with urllib.request.urlopen(cfg["jwks_url"]) as r:
            jwks = json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        logger.exception("Failed to fetch JWKS", extra=enrich({"error": str(exc)}))
        raise

    JWKS_CACHE["keys"] = jwks["keys"]
    JWKS_CACHE["ts"] = now

    logger.debug("JWKS fetched and cached", extra=enrich({"keys_count": len(jwks.get("keys", []))}))
    return JWKS_CACHE["keys"]

# =========================
# TOKEN VALIDATION
# =========================
def validate_jwt(token, cfg):
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        logger.exception("Failed to parse JWT header", extra=enrich({"error": str(exc)}))
        raise

    kid = header.get("kid")
    if not kid:
        logger.warning("JWT missing kid header")
        raise Exception("Missing kid")

    key = next((k for k in get_jwks(cfg) if k["kid"] == kid), None)
    if not key:
        logger.error("Public key not found for kid", extra=enrich({"kid": kid}))
        raise Exception("Public key not found")

    try:
        public_key = RSAAlgorithm.from_jwk(json.dumps(key))
    except Exception as exc:
        logger.exception("Failed to construct public key from JWK", extra=enrich({"kid": kid, "error": str(exc)}))
        raise

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=cfg["client_id"],
            issuer=cfg["issuer"]
        )
    except Exception as exc:
        logger.warning("JWT validation failed", extra=enrich({"kid": kid, "error": str(exc)}))
        raise

    logger.info("JWT validated", extra=enrich({"sub": claims.get("sub"), "kid": kid}))
    return claims

# =========================
# REQUEST NORMALIZATION
# =========================
def normalize_method_arn(method_arn):
    # arn:aws:execute-api:region:acct:apiId/stage/GET/resource
    parts = method_arn.split("/")
    method = parts[2]
    path = "/" + "/".join(parts[3:])

    # normalize path params
    path = path.replace("{id}", "*")

    return method, path

# =========================
# RBAC ENGINE
# =========================
def is_allowed(groups, method, path):
    resource = f"{method} {path}"

    for group in groups:
        rules = PERMISSIONS.get(group, {})
        allowed = rules.get("allow", [])

        for rule in allowed:
            if rule == "*":
                logger.debug("RBAC allow: wildcard", extra=enrich({"group": group, "resource": resource}))
                return True

            rule_method, rule_path = rule.split(" ")

            if rule_method != method:
                continue

            # wildcard path support
            if rule_path == path or rule_path.endswith("/*") and path.startswith(rule_path[:-1]):
                logger.debug("RBAC allow: matched rule", extra=enrich({"group": group, "rule": rule, "resource": resource}))
                return True

    logger.debug("RBAC deny: no matching rule", extra=enrich({"groups": groups, "resource": resource}))
    return False

# =========================
# POLICY CACHE
# =========================
def get_cached_policy(user_id, effect, resource):
    key = f"{user_id}:{effect}:{resource}"

    cached = POLICY_CACHE.get(key)
    if cached and time.time() - cached["ts"] < POLICY_TTL:
        return cached["policy"]

    policy = {
        "principalId": user_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": resource
            }]
        }
    }

    POLICY_CACHE[key] = {"policy": policy, "ts": time.time()}
    return policy

# =========================
# HANDLER
# =========================
def lambda_handler(event, context):
    logger.info(json.dumps(event))

    try:
        cfg = load_config()
        logger.info("cfg is : %s", cfg)

        token = event.get("authorizationToken")
        if not token or not token.startswith("Bearer "):
            raise Exception("Invalid token")
        logger.info("Token received, validating..." , token)
        jwt_token = token.split(" ")[1]
        logger.info("jwt_token is : %s", jwt_token)

        claims = validate_jwt(jwt_token, cfg)

        user_id = claims.get("sub", "unknown")
        groups = claims.get("cognito:groups", []) or []
        method_arn = event["methodArn"]
        logger.info("method_arn is : %s", method_arn)
        logger.info(json.dumps(claims))

        method, path = normalize_method_arn(method_arn)

        # RBAC decision
        allowed = is_allowed(groups, method, path)

        if not allowed:
            logger.warning(f"DENY user={user_id} groups={groups}")
            return get_cached_policy(user_id, "Deny", method_arn)

        logger.info(f"ALLOW user={user_id} groups={groups}")
        return get_cached_policy(user_id, "Allow", method_arn)

    except Exception as e:
        logger.error(f"AUTH ERROR: {str(e)}")
        return get_cached_policy("anonymous", "Deny", event.get("methodArn", "*"))