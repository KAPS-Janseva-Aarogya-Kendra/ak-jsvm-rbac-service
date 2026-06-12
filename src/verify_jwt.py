# import jwt
# from jwt import PyJWKClient
#
#
# class JWTVerifier:
#     def __init__(
#         self,
#         region: str,
#         user_pool_id: str,
#         client_id: str
#     ):
#         self.issuer = (
#             f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
#         )
#
#         self.client_id = client_id
#
#         self.jwks_url = (
#             f"{self.issuer}/.well-known/jwks.json"
#         )
#
#         self.jwks_client = PyJWKClient(self.jwks_url)
#
#     def verify(self, token: str) -> dict:
#         """
#         Verify JWT signature and claims.
#         Returns decoded claims if valid.
#         Raises exception if invalid.
#         """
#
#         signing_key = (
#             self.jwks_client.get_signing_key_from_jwt(token)
#         )
#
#         claims = jwt.decode(
#             token,
#             signing_key.key,
#             algorithms=["RS256"],
#             issuer=self.issuer,
#             audience=self.client_id,
#         )
#
#         return claims
#
#     def get_claim(self, token: str, claim_name: str):
#         claims = self.verify(token)
#         return claims.get(claim_name)