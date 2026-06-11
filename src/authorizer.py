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

def lambda_handler(event, context):
    logger.info(f" Authorizer event: {json.dumps(event)}")