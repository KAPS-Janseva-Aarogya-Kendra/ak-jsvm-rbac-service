import json
import logging
import os
import time
from logging import Logger
from typing import Dict, Any, List, Optional

import boto3
import jwt
from jwt.jwks_client import PyJWKClient

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
session = boto3.session.Session()
ssm = session.client('ssm')
s3 = session.client('s3')

# Environment (CloudFormation sets RBAC_BUCKET_SSM to the SSM parameter name)
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
RBAC_BUCKET_SSM = os.environ.get('RBAC_BUCKET_SSM', f"/{ENVIRONMENT}/jsvm/rbac-bucket-name")
COGNITO_USER_POOL_ID_SSM = os.environ.get('COGNITO_USER_POOL_ID_SSM', f"/{ENVIRONMENT}/jsvm/cognito-user-pool-id")
COGNITO_APP_CLIENT_ID_SSM = os.environ.get('COGNITO_APP_CLIENT_ID_SSM', f"/{ENVIRONMENT}/jsvm/cognito-client-id")

VERIFY_JWT = os.environ.get('VERIFY_JWT', 'true').lower() in ('1', 'true', 'yes')


def get_ssm_parameter(name: str) -> str:
    resp = ssm.get_parameter(Name=name)
    return resp['Parameter']['Value']

def load_rbac_policy() -> Dict[str, Any]:
    """Load RBAC policy JSON. Try S3 (production) then fall back to local file (dev/test)."""
    try:
        bucket = get_ssm_parameter(RBAC_BUCKET_SSM)
        key = f"{ENVIRONMENT}/rbac-policy.json"
        logger.info(f"Loading RBAC policy from s3://{bucket}/{key}")
        resp = s3.get_object(Bucket=bucket, Key=key)
        content = resp['Body'].read().decode('utf-8')
        return json.loads(content)
    except Exception as e:
        logger.info(f"Could not load RBAC policy from S3: {e}; falling back to local file")
        local_path = os.path.join(os.path.dirname(__file__), '..', 'rbac-policies', ENVIRONMENT, 'rbac-policy.json')
        local_path = os.path.normpath(local_path)
        try:
            with open(local_path, 'r') as f:
                return json.load(f)
        except Exception:
            logger.warning("No RBAC policy found locally; defaulting to empty policy")
            return {'roles': {}}


def get_jwks_url(user_pool_id: str) -> str:
    region = session.region_name or os.environ.get('AWS_REGION', 'us-west-2')
    return f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"

def get_aws_region():
    region = os.environ["AWS_REGION"]
    if not region:
        region = "us-west-2"
    return region

def get_claims(token):
    USER_POOL_ID = get_ssm_parameter(COGNITO_USER_POOL_ID_SSM)
    REGION = get_aws_region()
    jwks_client = PyJWKClient(jwks_url = get_jwks_url())
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}",
        audience=get_ssm_parameter(COGNITO_APP_CLIENT_ID_SSM)
    )




def parse_method_and_path(method_arn: str) -> (str, str):
    """Extract HTTP method and resource path from methodArn.

    method_arn example: arn:aws:execute-api:region:acct:api-id/stage/GET/resource/path
    """
    try:
        parts = method_arn.split(':')[-1].split('/')
        # parts = [api-id, stage, HTTP-VERB, resource, ...]
        http_method = parts[2]
        resource = '/' + '/'.join(parts[3:]) if len(parts) > 3 else '/'
        return http_method.upper(), resource
    except Exception:
        return '', '/'


def permission_matches(permission: str, method: str, path: str) -> bool:
    """Check whether a permission string matches the requested method and path.

    Permission formats supported:
      - "*" (allow everything)
      - "GET:/users" (method:path prefix match)
    """
    if permission == '*' or permission == '"*"':
        return True
    try:
        perm_method, perm_path = permission.split(':', 1)
    except ValueError:
        return False
    if perm_method != method:
        return False
    # allow prefix matching
    if perm_path == '*' or path.startswith(perm_path):
        return True
    return False


def build_policy(principal: str, effect: str, resource: str = '*') -> Dict[str, Any]:
    return {
        'principalId': principal,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': resource
                }
            ]
        }
    }


def lambda_handler(event, context) -> Dict[str, Any]:
    logger.info(f" Authorizer event: {json.dumps(event)}")

    token = event.get('authorizationToken', '')
    if token.startswith('Bearer '):
        token = token[len('Bearer '):]

    if not token:
        logger.warning('No authorization token provided')
        raise Exception('Unauthorized')

    method_arn = event.get('methodArn', '')
    method, path = parse_method_and_path(method_arn)

    # Decode / verify token
    try:
        claims = get_claims(token)
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise Exception('Unauthorized')

    principal = claims.get('sub') or claims.get('username') or 'anonymous'

    # Determine role: claim 'role' > cognito:groups first entry > users mapping in policy
    role = claims.get('role')
    if not role and 'cognito:groups' in claims:
        groups = claims.get('cognito:groups')
        if isinstance(groups, list) and groups:
            role = groups[0]

    policy = load_rbac_policy()
    roles = policy.get('roles', {})
    Logger.info(f"Loaded RBAC policy with roles: {list(roles.keys())}")
    #
    # # If still no role, try users mapping in policy (optional)
    # if not role:
    #     users_map = policy.get('users', {})
    #     role = users_map.get(principal)
    #
    # if not role:
    #     role = 'USER'
    #
    # # Evaluate permissions
    # role_def = roles.get(role, {})
    # permissions: List[str] = role_def.get('permissions', []) if role_def else []
    #
    # allowed = False
    # for perm in permissions:
    #     if permission_matches(perm, method, path):
    #         allowed = True
    #         break
    #
    # effect = 'Allow' if allowed else 'Deny'
    # auth_response = build_policy(principal, effect, '*')
    # # context values must be strings
    # auth_response['context'] = {
    #     'role': role,
    # }

    # logger.info(f"Auth response for {principal}: effect={effect}, role={role}, method={method}, path={path}")
    return roles.get(role)

