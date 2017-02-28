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
from requests.exceptions import HTTPError
from urlparse import urlparse
from urllib import quote_plus

from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.conf import settings

from wstore.asset_manager.resource_plugins.plugin import Plugin
from wstore.asset_manager.resource_plugins.plugin_error import PluginError
from wstore.store_commons.errors import ConflictError

from .config import *
from .keystone_client import KeystoneClient


class OrionPlugin(Plugin):

    def _get_user_id(self, keystone_client, domain_id, username):
        # Get provider and seller role ids
        users = keystone_client.get_user_by_name(username)
        user_info = [user for user in users['users'] if user['domain_id'] == domain_id]

        if not len(user_info):
            raise PluginError('Your user is not registered in the underlying Keystone instance')

        return user_info[0]['id']

    def _generate_api_key(self, parsed_url):
        proxy_admin_url = parsed_url.scheme + '://' + parsed_url.netloc
        authorize_url = settings.AUTHORIZE_SERVICE

        # Generate an API key using the authorization service
        resp = requests.post(authorize_url, json={
            'url': proxy_admin_url
        })

        if resp.status_code != 201:
            raise PluginError('Error generating an API key')

        # Send the API key to the proxy using the accounting administration service
        acc_resp = requests.post(proxy_admin_url + '/accounting/token', json={
            'apiKey': resp.json()['apiKey']
        })

        if acc_resp.status_code != 201:
            raise PluginError('The accounting service has failed saving the API key')

    def on_post_product_spec_validation(self, provider, asset):
        # Extract related information from the asset
        parsed_url = urlparse(asset.download_link)

        try:
            # Log the plugin in the Keystone instance
            keystone_client = KeystoneClient(KEYSTONE_USER, KEYSTONE_PWD, ADMIN_DOMAIN, parsed_url.scheme, parsed_url.hostname)

            # Get available services with the provided name
            service_info = keystone_client.get_project_by_name(asset.meta_info['service'])

            if not len(service_info['projects']):
                raise ObjectDoesNotExist('The FIWARE service path ' + asset.meta_info['service'] + ' could not be found')

            # It is possible to have the same service path in different domains
            # so the domain id is used in order to validate the domain field
            project_id = None
            domain_id = None
            for project in service_info['projects']:
                domain_info = keystone_client.get_domain_by_id(project['domain_id'])

                if domain_info['domain']['name'].lower() == asset.meta_info['tenant'].lower():
                    # Save the project id and domain id to used then in future requests
                    project_id = project['id']
                    domain_id = project['domain_id']
                    break
            else:
                raise ObjectDoesNotExist('The FIWARE service' + asset.meta_info['tenant'] + ' could not be found')

            # Check that the provided role exists (The SCIM plugin is being used so the project role is done by
            # composing it with the project id)
            role_info = keystone_client.get_role_by_name(quote_plus(domain_id + '#' + asset.meta_info['role']))

            if not len(role_info['roles']):
                raise ObjectDoesNotExist('The role' + asset.meta_info['role'] + ' is not defined for service path ' + asset.meta_info['service'])

            role_id = role_info['roles'][0]['id']

            provider_id = self._get_user_id(keystone_client, domain_id, provider.name)

            seller_role_info = keystone_client.get_role_by_name(quote_plus(domain_id + '#' + SELLER_ROLE))

            if not len(seller_role_info['roles']):
                raise PluginError(
                    'The configured seller role is not valid in the underlying Keystone instance')

            seller_role_id = seller_role_info['roles'][0]['id']

        except HTTPError:
            raise PluginError('It has not been possible to connect with Keystone')

        # Validate provider permissions
        try:
            keystone_client.check_role(project_id, provider_id, seller_role_id)
        except HTTPError as e:
            # The role assignment does not exist; thus the user is not authorized
            if e.response.status_code == 404:
                raise PermissionDenied(
                    'You are not authorized to create offerings for the specified FIWARE service path')
            else:
                raise PluginError('It has not been possible to connect with Keystone')

        # Generate an API Key for accounting Info
        self._generate_api_key(parsed_url)

        # Save related metadata to avoid future requests
        asset.meta_info['project_id'] = project_id
        asset.meta_info['domain_id'] = domain_id
        asset.meta_info['role_id'] = role_id
        asset.save()

    def on_post_product_offering_validation(self, asset, product_offering):
        # Parse the pricing models to check usage models
        provided_usage = [price_model['unitsOfMeasure']
                          for price_model in product_offering['productOfferingPrice']
                          if price_model['priceType'].lower() == 'usage'] if 'productOfferingPrice' in product_offering else []

        if provided_usage:
            # Get the valid models
            parsed_url = urlparse(asset.get_url())
            units_service = parsed_url.scheme + '://' + parsed_url.netloc + '/accounting/units'

            resp = requests.get(units_service)
            valid_units = resp.json()

            # Check that all usage models are supported
            for model in provided_usage:
                if model not in valid_units['units']:
                    raise PluginError('The usage model ' + model + ' is not supported by the accounting service')

    def _notify_accounting(self, asset, order, contract, type_):
        parsed_url = urlparse(asset.download_link)
        notification = {
            'orderId': unicode(order.order_id),
            'productId': unicode(contract.product_id),
        }

        if type_ == 'add':
            notification['customer'] = order.customer.username
            notification['acquisition'] = {
                'roleId': asset.meta_info['role_id'],
                'domain': asset.meta_info['tenant'],
                'servicePath': asset.meta_info['service'],
                'unit': [price_model['unit'] for price_model in contract.pricing_model['pay_per_use']][0]
            }

        url = parsed_url.scheme + '://' + parsed_url.netloc + '/accounting/acquisitions/' + type_

        resp = requests.post(url, json=notification)
        if resp.status_code != 201:
            raise PluginError('Error notifying the product acquisition to the accounting server')

    def on_product_acquisition(self, asset, contract, order):
        # Extract related information from the asset
        parsed_url = urlparse(asset.download_link)

        try:
            keystone_client = KeystoneClient(KEYSTONE_USER, KEYSTONE_PWD, ADMIN_DOMAIN, parsed_url.scheme, parsed_url.hostname)

            # Check the customer user
            customer_id = self._get_user_id(keystone_client, asset.meta_info['domain_id'], order.owner_organization.name)

            # Give the user the new role
            keystone_client.grant_role(asset.meta_info['project_id'], customer_id, asset.meta_info['role_id'])

        except HTTPError as e:
            if e.response.status_code == 409:
                raise ConflictError('You already own the offered role')
            else:
                raise PluginError('It has not been possible to connect with Keystone')

        # If the model is usage, send usage notification
        if 'pay_per_use' in contract.pricing_model:
            self._notify_accounting(asset, order, contract, 'add')

    def on_product_suspension(self, asset, contract, order):
        parsed_url = urlparse(asset.download_link)

        try:
            keystone_client = KeystoneClient(KEYSTONE_USER, KEYSTONE_PWD, ADMIN_DOMAIN, parsed_url.scheme, parsed_url.hostname)

            # Check the customer user
            customer_id = self._get_user_id(keystone_client, asset.meta_info['domain_id'], order.owner_organization.name)

            # Remove the role from the user
            keystone_client.revoke_role(asset.meta_info['project_id'], customer_id, asset.meta_info['role_id'])

        except HTTPError:
            raise PluginError('It has not been possible to connect with Keystone')

        # If the model is usage, send usage notification
        if 'pay_per_use' in contract.pricing_model:
            self._notify_accounting(asset, order, contract, 'remove')
