# -*- coding: utf-8 -*-

# Copyright (c) 2017 CoNWeT Lab., Universidad Politécnica de Madrid

# This file belongs to the secured orion plugin
# of the Business API Ecosystem.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import requests


class KeystoneClient:

    _access_token = None
    _server = None
    _domain = None

    def __init__(self, user, password, domain, protocol, host, port=5000):
        self._domain = domain
        self._server = protocol + '://' + host + ':' + unicode(port)
        self._access_token = self._login(user, password)

    def _login(self, user, password):
        url = self._server + '/v3/auth/tokens'

        login_resp = requests.post(url, json={
            "auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "domain": {
                                "name": self._domain
                            },
                            "name": user,
                            "password": password
                        }
                    }
                },
                "scope": {
                    "domain": {
                        "name": self._domain
                    }
                }
            }
        })

        login_resp.raise_for_status()
        return login_resp.headers.get('X-Subject-Token', '')

    def _make_get_request(self, url):
        resp = requests.get(url, headers={
            'X-Auth-Token': self._access_token
        })

        resp.raise_for_status()
        return resp.json()

    def get_project_by_name(self, project_name):
        return self._make_get_request(self._server + '/v3/projects?name=' + project_name)

    def get_domain_by_id(self, domain_id):
        return self._make_get_request(self._server + '/v3/domains/' + domain_id)

    def get_role_by_name(self, role_name):
        return self._make_get_request(self._server + '/v3/roles?name=' + role_name)

    def get_user_by_name(self, username):
        return self._make_get_request(self._server + '/v3/users?name=' + username)

    def check_role(self, project_id, user_id, role_id):
        return self._make_get_request(self._server + '/v3/projects/' + project_id + '/users/' + user_id + '/roles/' + role_id)

    def _make_role_request(self, project_id, user_id, role_id, method):
        url = self._server + '/v3/projects/' + project_id + '/users/' + user_id + '/roles/' + role_id
        resp = method(url, headers={
            'X-Auth-Token': self._access_token
        })

        resp.raise_for_status()

    def grant_role(self, project_id, user_id, role_id):
        self._make_role_request(project_id, user_id, role_id, requests.put)

    def revoke_role(self, project_id, user_id, role_id):
        self._make_role_request(project_id, user_id, role_id, requests.delete)
