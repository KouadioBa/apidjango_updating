from django.utils import timezone
from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from rest_framework.authtoken.models import Token
import datetime,pytz

class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        try:
            token = Token.objects.get(key=key)
        except Token.DoesNotExist:
            raise AuthenticationFailed('Token invalide')

        if not token.user.is_active:
            raise AuthenticationFailed('Utilisateur inactif')
        
        utc_now = datetime.datetime.utcnow()
        utc_now = utc_now.replace(tzinfo=pytz.utc)

        if token.created < utc_now - datetime.timedelta(seconds=7200):
            raise AuthenticationFailed('Le token a expiré')

        return token.user, token