import json
import logging
import os

from auth import auth_base
from model import model_helper


LOGGER = logging.getLogger('script_server.StaticAuthorizer')

class StaticAuthenticator(auth_base.Authenticator):
    def __init__(self, params_dict):
        super().__init__()

        self._users = self._load_users(params_dict)

    def authenticate(self, request_handler):
        username = request_handler.get_argument('username')
        password = request_handler.get_argument('password')

        LOGGER.info('Logging in user ' + username)

        if username in self._users and self._users[username] == password:
            return username

        LOGGER.info('Invalid credentials for user ' + username)
        raise auth_base.AuthRejectedError('Invalid credentials')

    def _load_users(self, params_dict):
        users  = model_helper.read_obligatory(params_dict, 'static_users', ' list')

        if not isinstance(users, dict):
            raise Exception('"static_users" has invalid type. Dictionary expected.')

        return users

    def _get_groups(self, user):
        groups = self._users.get(user)
        if groups is not None:
            return groups

        groups = []
        self._user_groups[user] = groups
        return groups

    def get_groups(self, user, known_groups=None):
        return self._get_groups(user)

