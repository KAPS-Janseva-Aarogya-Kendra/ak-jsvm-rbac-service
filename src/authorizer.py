import json
import time
import logging
import urllib.request
import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# =========================
# ENV VARIABLES
# =========================
COGNITO_REGION = "us-west-2"
USER_POOL_ID = "us-west-2_xxxxx"
APP_CLIENT_ID = "xxxxxxxxxxxx"

ISSUER = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USER_POOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

# =========================
# SIMPLE IN-MEMORY CACHE
# =========================
JWKS_CACHE = {
    "keys": None,
    "last_fetch": 0,
    "ttl_seconds": 3600
}

# =========================
# JWKS FETCH
# =========================
def get_jwks():
    now = time.time()

    if JWKS_CACHE["keys"] and (now - JWKS_CACHE["last_fetch"] < JWKS_CACHE["ttl_seconds"]):
        return JWKS_CACHE["keys"]

    logger.info("Fetching JWKS from Cognito")

    with urllib.request.urlopen(JWKS_URL) as response:
        jwks = json.loads(response.read().decode("utf-8"))

    JWKS_CACHE["keys"] = jwks["keys"]
    JWKS_CACHE["last_fetch"] = now

    return JWKS_CACHE["keys"]

# =========================
# TOKEN VALIDATION
# =========================
def validate_token(token: str):
    headers = jwt.get_unverified_header(token)

    kid = headers.get("kid")
    if not kid:
        raise Exception("Missing kid in token")

    jwks = get_jwks()

    key = next((k for k in jwks if k["kid"] == kid), None)
    if not key:
        raise Exception("Public key not found")

    public_key = RSAAlgorithm.from_jwk(json.dumps(key))

    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=APP_CLIENT_ID,
        issuer=ISSUER
    )

    return claims

# =========================
# RBAC LOGIC
# =========================
def check_permissions(claims, method_arn):
    """
    Example RBAC based on Cognito groups
    """

    groups = claims.get("cognito:groups", [])

    # Example rules
    if "admin" in groups:
        return True

    if "USER" in groups and "GET" in method_arn:
        return True

    if "USER" in groups and "POST" in method_arn:
        return False

    return False

# =========================
# IAM POLICY BUILDER
# =========================
def generate_policy(principal_id, effect, resource):
    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": resource
            }]
        }
    }

# =========================
# MAIN HANDLER
# =========================
def lambda_handler(event, context):
    logger.info(json.dumps(event))

    try:
        token = event.get("authorizationToken")

        if not token:
            raise Exception("Missing token")

        if not token.startswith("Bearer "):
            raise Exception("Invalid token format")

        jwt_token = token.split(" ")[1]

        # 1. Validate JWT
        claims = validate_token(jwt_token)

        user_id = claims.get("sub", "unknown")

        # 2. RBAC check
        method_arn = event["methodArn"]

        if not check_permissions(claims, method_arn):
            logger.warning("Access denied for user %s", user_id)
            return generate_policy(user_id, "Deny", method_arn)

        # 3. Allow
        logger.info("Access granted for user %s", user_id)
        return generate_policy(user_id, "Allow", method_arn)

    except Exception as e:
        logger.error(f"Authorization failed: {str(e)}")

        # Fail CLOSED (important for security)
        return generate_policy("anonymous", "Deny", event.get("methodArn", "*"))