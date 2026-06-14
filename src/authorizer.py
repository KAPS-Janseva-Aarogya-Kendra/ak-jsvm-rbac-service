import json
import time
import logging
import os
import boto3
import jwt
from jwt import PyJWKClient

# Structured logger configuration
# SERVICE_NAME = os.environ.get("SERVICE_NAME", "authorizer")
LOG_LEVEL = "INFO"
logger = logging.getLogger("authorizer")
logger.setLevel(LOG_LEVEL)

ssm = boto3.client("ssm", region_name= "us-west-2")

# =========================
# CACHE
# =========================
CONFIG_CACHE = {"loaded": False}
POLICY_CACHE = {}
POLICY_TTL = 300  # 5 min per user cache limit

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
    # user_pool_id = ssm.get_parameter(
    #     Name=os.environ["COGNITO_USER_POOL_ID_SSM"],
    #     WithDecryption=False
    # )["Parameter"]["Value"]
    #
    # client_id = ssm.get_parameter(
    #     Name=os.environ["COGNITO_CLIENT_ID_SSM"],
    #     WithDecryption=False
    # )["Parameter"]["Value"]

    region = "us-west-2"
    user_pool_id = "us-west-2_rz5DMPdzH"
    client_id = "1uo4l9ki6s97qlupr5vjkel8vh"

    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    jwks_url = f"{issuer}/.well-known/jwks.json"

    CONFIG_CACHE.update({
        "loaded": True,
        "user_pool_id": user_pool_id,
        "client_id": client_id,
        "region": region,
        "issuer": issuer,
        "jwks_url": jwks_url,
        # Instantiate PyJWKClient directly to handle automatic HTTP fetching & internal caching
        "jwks_client": PyJWKClient(jwks_url)
    })

    logger.info("Configuration loaded CONFIG_CACHE %s ", CONFIG_CACHE)
    return CONFIG_CACHE


# =========================
# TOKEN EXTRACTION & VALIDATION
# =========================
def extract_and_validate_token(auth_header):
    """
    Extract JWT from Authorization header and validate format.
    
    Expected format: "Bearer <token>"
    Token must have 3 segments: header.payload.signature
    
    Args:
        auth_header: Authorization header value
        
    Returns:
        str: Extracted JWT token
        
    Raises:
        Exception: If token format is invalid
    """
    if not auth_header:
        logger.warning("Missing authorization header")
        raise Exception("Missing authorization header")
    
    if not isinstance(auth_header, str):
        logger.warning("Authorization header is not a string")
        raise Exception("Invalid authorization header type")
    
    auth_header = auth_header.strip()
    
    if not auth_header.startswith("Bearer "):
        logger.warning("Authorization header does not start with 'Bearer'")
        raise Exception("Invalid authorization header format: expected 'Bearer <token>'")
    
    # Extract token after "Bearer "
    token_part = auth_header[7:]  # Skip "Bearer "
    
    if not token_part:
        logger.warning("Missing token after 'Bearer'")
        raise Exception("Missing token after 'Bearer'")
    
    # Validate token has 3 segments (header.payload.signature)
    segments = token_part.split(".")
    if len(segments) != 3:
        logger.warning("Invalid JWT format: expected 3 segments (header.payload.signature), got %d", len(segments))
        raise Exception(f"Invalid JWT format: expected 3 segments, got {len(segments)}")
    
    # Verify segments are not empty
    for i, segment in enumerate(segments):
        if not segment:
            logger.warning("JWT segment %d is empty", i)
            raise Exception(f"JWT segment {i} is empty")
    
    logger.debug("Token extracted and format validated")
    return token_part


# =========================
# TOKEN VALIDATION
# =========================
def validate_jwt(token, cfg):
    try:
        logger.debug("Starting JWT validation")
        # Automatically extracts the kid, matches it against the JWKS endpoint, and handles RSA wrapping
        jwks_client = cfg["jwks_client"]
        
        logger.debug("Extracting signing key from JWKS")
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        logger.debug("Decoding JWT with RS256 algorithm")
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=cfg["client_id"],
            issuer=cfg["issuer"]
        )
        logger.info("JWT validated successfully for sub=%s", claims.get("sub", "unknown"))
        return claims
    except jwt.DecodeError as exc:
        logger.error("JWT decode error: %s", str(exc), exc_info=exc)
        raise Exception(f"Invalid token signature or format: {str(exc)}")
    except jwt.ExpiredSignatureError as exc:
        logger.error("JWT expired: %s", str(exc))
        raise Exception("Token has expired")
    except jwt.InvalidTokenError as exc:
        logger.error("Invalid JWT token: %s", str(exc), exc_info=exc)
        raise Exception(f"Invalid token: {str(exc)}")
    except Exception as exc:
        logger.error("JWT validation failed: %s", str(exc), exc_info=exc)
        raise Exception("Unauthorized")


# =========================
# REQUEST NORMALIZATION
# =========================
def normalize_method_arn(method_arn):
    # Format standard: arn:aws:execute-api:region:acct:apiId/stage/GET/resource
    parts = method_arn.split("/")
    method = parts[2]
    path = "/" + "/".join(parts[3:])

    # Normalize incoming path variables
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
                logger.debug("RBAC allow: wildcard")
                return True

            rule_method, rule_path = rule.split(" ")

            if rule_method != method:
                continue

            # Wildcard path support
            if rule_path == path or (rule_path.endswith("/*") and path.startswith(rule_path[:-1])):
                logger.debug("RBAC allow: matched rule")
                return True

    logger.debug("RBAC deny: no matching rule")
    return False


# =========================
# POLICY BUILDER & CACHE
# =========================
def get_cached_policy(user_id, effect, resource, groups=None):
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
        },
        # Pass context details securely downstream to backend targets
        "context": {
            "userId": user_id,
            "groups": ",".join(groups) if groups else ""
        }
    }

    POLICY_CACHE[key] = {"policy": policy, "ts": time.time()}
    return policy


# =========================
# HANDLER
# =========================
def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))
    method_arn = event.get("methodArn", "")

    try:
        cfg = load_config()

        auth_header = event.get("authorizationToken")
        # Extract and validate token format before attempting JWT decode
        jwt_token = extract_and_validate_token(auth_header)
        claims = validate_jwt(jwt_token, cfg)

        user_id = claims.get("sub", "unknown")
        groups = claims.get("cognito:groups", []) or []

        method, path = normalize_method_arn(method_arn)
        logger.info("Processing request %s %s", method, path)

        # Evaluate RBAC rules matrix
        if is_allowed(groups, method, path):
            logger.info("Access granted %s ", user_id)
            return get_cached_policy(user_id, "Allow", method_arn, groups)
        else:
            logger.warning("Access denied by RBAC constraints")
            return get_cached_policy(user_id, "Deny", method_arn, groups)

    except Exception as exc:
        logger.exception("Authorizer execution exception encountered", exc_info=exc)
        # Safely return an explicit deny architecture instead of throwing a raw 500 error to the client
        fallback_resource = method_arn if method_arn else "*"
        return get_cached_policy("anonymous", "Deny", fallback_resource)
