# biz-secured-orion-plugin

Business API Ecosystem plugin for offering orion CB queries and services when a Keystone + PEP + PDP are used for security. This plugin validates that all the provided meta info is valid and checks whether the seller is authorized to create products regarding the specific Keystone instance.

The main feature of this plugin is managing Keystone roles, so when customers aquire an offering which include an asset of the defined type, they are granted a particular role (linked to a PDP policy). In this way, customers will be able to access the acquired CB protected by a FIWARE PEP. 

This plugin defines three metadata fields that must be provided when creating Business API Ecosystem product specs. In particular, it requires:

* *tenant* (labeled as FIWARE Service): Tenant (Keystone domain) where the offered CB services belong
* *service* (labeled as FIWARE Service path): Service path (Keystone project) where the offered CB services belong
* *role*: Role to be granted to customers that acquire the involved assets

## Configuration

The secured orion plugin requires to be configured by providing the following fields, located in *config.py*

* *KEYSTONE_USER*: Keystone user that will be used by the plugin in order to interact with Keystone APIs
* *KEYSTONE_PWD*: Password of the Keystone user used by the plugin
* *ADMIN_DOMAIN*: Administration domain where the Keystone user will be logged in
* *SELLER_ROLE*: Role that sellers must have in a Keystone domain in order to be allowed to create product specs with Keystone assets

## Installation

To install the plugin, the first thing that you must do is to compress it in a ZIP file. To do so, you can run the following command:

```
zip secured-orion.zip package.json orion_plugin.py keystone_client.py config.py
```

Then, go the src directory included in the folder used to install the Business Ecosystem Charging Backend, and run the following command:

```
./manage.py loadplugin <PATH_TO_THE_ZIP_FILE>
```

