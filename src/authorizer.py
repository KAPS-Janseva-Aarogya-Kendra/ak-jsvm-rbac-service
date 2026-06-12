import json
import os
import time
import logging
import boto3
import urllib.request
import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
        return CONFIG_CACHE

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

    return CONFIG_CACHE

# =========================
# JWKS CACHE
# =========================
def get_jwks(cfg):
    now = time.time()

    if JWKS_CACHE["keys"] and now - JWKS_CACHE["ts"] < JWKS_TTL:
        return JWKS_CACHE["keys"]

    with urllib.request.urlopen(cfg["jwks_url"]) as r:
        jwks = json.loads(r.read().decode("utf-8"))

    JWKS_CACHE["keys"] = jwks["keys"]
    JWKS_CACHE["ts"] = now

    return JWKS_CACHE["keys"]

# =========================
# TOKEN VALIDATION
# =========================
def validate_jwt(token, cfg):
    header = jwt.get_unverified_header(token)

    kid = header.get("kid")
    if not kid:
        raise Exception("Missing kid")

    key = next((k for k in get_jwks(cfg) if k["kid"] == kid), None)
    if not key:
        raise Exception("Public key not found")

    public_key = RSAAlgorithm.from_jwk(json.dumps(key))

    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=cfg["client_id"],
        issuer=cfg["issuer"]
    )

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
                return True

            rule_method, rule_path = rule.split(" ")

            if rule_method != method:
                continue

            # wildcard path support
            if rule_path == path or rule_path.endswith("/*") and path.startswith(rule_path[:-1]):
                return True

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

        token = event.get("authorizationToken")
        if not token or not token.startswith("Bearer "):
            raise Exception("Invalid token")
        logger.info("Token received, validating..." , token)
        jwt_token = token.split(" ")[1]

        claims = validate_jwt(jwt_token, cfg)

        user_id = claims.get("sub", "unknown")
        groups = claims.get("cognito:groups", []) or []
        method_arn = event["methodArn"]

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