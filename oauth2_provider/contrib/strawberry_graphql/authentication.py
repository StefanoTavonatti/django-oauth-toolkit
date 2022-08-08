from django.core.exceptions import SuspiciousOperation

from oauth2_provider.backends import OAuth2Backend
from oauth2_provider.oauth2_backends import get_oauthlib_core


class StrawberryOauth2Backend(OAuth2Backend):
    def authenticate(self, request=None, **credentials):
        oauthlib_core = get_oauthlib_core()
        if request is not None:
            try:
                valid, request = oauthlib_core.verify_request(request, scopes=[])
            except ValueError as error:
                if str(error) == "Invalid hex encoding in query string.":
                    raise SuspiciousOperation(error)
                else:
                    raise
            else:
                if valid:
                    user = request.user

                    # Annotating the user with the used oauth2 token
                    user.used_oauth_token = request.access_token
                    return request.user

        return None
