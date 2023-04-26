from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: gcp_secret_manager
version_added: "1.0.0"
author:
    - Prashant Pokhriyal (https://github.com/Devopcasting)
description: Secret Manager lets you store, manage and secure access to your application secrets
options:
    name:
        description: Give the name for your secret
        required: true
        type: str

    project_id:
        description: Give the name of the GCP project id, where secret will be created
        required: true
        type: str

    secret_file:
        description: Give the local path of the file containing your secret/sensitive datas
        required: true
        type: str
    
    disable_secret_version:
        description: Disable the given secret version. Future requests will throw an error until
                     the secret version is enabled. Other secrets versions are unaffected.
        type: int

    enable_secret_version:
        description: Enable the given secret version, enabling it to be accessed after
                     previously being disabled. Other secrets versions are unaffected.
        type: int

    destroy_secret_version:
        description: Destroy the given secret version, making the payload irrecoverable. Other
                     secrets versions are unaffected.
        type: int
    
    state:
        description: Define the state of the secret
        type: str
        default: present
        choices: present or absent
'''

from ansible.module_utils.basic import AnsibleModule
from google.cloud import secretmanager
import google_crc32c
import os

def create_secret(**kwargs) -> str:
    # Create the Secret Manager client
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the parent project
    parent = f"projects/{kwargs['project_id']}"

    # Build a dict of settings for the secret
    secret = {'replication':{'automatic':{}}}

    # Create the secret
    response = client.create_secret(secret_id=kwargs['secret_name'], parent=parent, secret=secret)

    # Build the resource name of the parent secret
    parent_secret = f"{response.name}"

    # Convert the string payload into bytes
    with open(kwargs['secret_file_name'],'r') as f:
        payload = f.read().encode('UTF-8')

    # Add the secret version
    secret_response = client.add_secret_version(parent=parent_secret, payload={'data':payload})
    return f"Added secret version: {secret_response.name}"

# list all available secrets
def list_all_secrets(**kwargs) -> list:
    # Create the Secret Manager client
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the parent project
    parent = f"projects/{kwargs['project_id']}"

    # Generate secret list
    secret_list = [secret.name for secret in client.list_secrets(request={"parent":parent})]

    return secret_list

# add new version of secret
def add_secret_version(**kwargs) -> str:

    # Import the Secret Manager client library.
    from google.cloud import secretmanager

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the parent secret.
    parent = client.secret_path(kwargs['project_id'], kwargs['secret_name'])

    # Convert the string payload into a bytes. This step can be omitted if you
    # pass in bytes instead of a str for the payload argument.
    with open(kwargs['secret_file_name'],'r') as f:
        payload = f.read().encode('UTF-8')

    # Calculate payload checksum. Passing a checksum in add-version request
    # is optional.
    crc32c = google_crc32c.Checksum()
    crc32c.update(payload)

    # Add the secret version.
    response = client.add_secret_version(
        request={
            "parent": parent,
            "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
        }
    )
    return f"Added secret version: {response.name}"


def delete_secret(project_id, secret_id) -> str:
    """
    Delete the secret with the given name and all of its versions.
    """

    # Import the Secret Manager client library.
    from google.cloud import secretmanager

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret.
    name = client.secret_path(project_id, secret_id)

    # Delete the secret.
    client.delete_secret(request={"name": name})

    return f"Deleted secret version: {secret_id}"


def disable_secret_version(project_id, secret_id, version_id):
    """
    Disable the given secret version. Future requests will throw an error until
    the secret version is enabled. Other secrets versions are unaffected.
    """

    # Import the Secret Manager client library.
    from google.cloud import secretmanager

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    try:
        # Disable the secret version.
        response = client.disable_secret_version(request={"name": name})
        return f"Disabled secret version: {response.name}"
    except Exception:
        return f"Invalid secret version"

def destroy_secret_version(project_id, secret_id, version_id):
    """
    Destroy the given secret version, making the payload irrecoverable. Other
    secrets versions are unaffected.
    """

    # Import the Secret Manager client library.
    from google.cloud import secretmanager

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    try:
        # Destroy the secret version.
        response = client.destroy_secret_version(request={"name": name})
        return f"Destroyed secret version: {response.name}"
    except Exception:
        return f"Invalid secret version"

def enable_secret_version(project_id, secret_id, version_id):
    """
    Enable the given secret version, enabling it to be accessed after
    previously being disabled. Other secrets versions are unaffected.
    """

    # Import the Secret Manager client library.
    from google.cloud import secretmanager

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    try:
        # Disable the secret version.
        response = client.enable_secret_version(request={"name": name})
        return f"Enabled secret version: {response.name}"
    except Exception:
        return f"Invalid secret version"


def run_module():

    # available arguments/parameters a user can pass to the module
    module_args = dict(
            name=dict(type='str', required=True),
            project_id=dict(type='str', required=True),
            secret_file=dict(type='str', required=True),
            disable_secret_version=dict(type='int'),
            enable_secret_version=dict(type='int'),
            destroy_secret_version=dict(type='int'),
            state=dict(type='str', choices=['present', 'absent'], default='present')
            )

    # result dict
    result = dict(
            changed=False,
            msg=''
            )

    # passing module arguments to AnsibleModule
    module = AnsibleModule(argument_spec=module_args)

    # get the arguments values
    PROJECT_ID = module.params['project_id']
    SECRET_NAME = module.params['name']
    SECRET_FILE = module.params['secret_file']

    # check secret is already available
    get_secret_list = list_all_secrets(project_id=PROJECT_ID)
    secrets_list = [ i.split('/')[::-1][0] for i in get_secret_list ]

    if module.params['state'] == "absent":
        if module.params['name'] not in secrets_list:
            result['msg'] = "Secret not available for deletion"
            module.fail_json(**result)
        else:
            result['msg'] = delete_secret(project_id=PROJECT_ID, secret_id=SECRET_NAME)
            module.exit_json(**result)
    else:
        if module.params['disable_secret_version'] is not None:
            if module.params['name'] not in secrets_list:
                result['msg'] = "Secret version not available."
                module.fail_json(**result)
            else:
                result['msg'] = disable_secret_version(project_id=PROJECT_ID, secret_id=SECRET_NAME, 
                                                       version_id=module.params['disable_secret_version'])
                module.exit_json(**result)

        if module.params['enable_secret_version'] is not None:
            if module.params['name'] not in secrets_list:
                result['msg'] = "Secret version not available."
                module.fail_json(**result)
            else:
                result['msg'] = enable_secret_version(project_id=PROJECT_ID, secret_id=SECRET_NAME,
                                                      version_id=module.params['enable_secret_version'])
                module.exit_json(**result)

        if module.params['destroy_secret_version'] is not None:
            if module.params['name'] not in secrets_list:
                result['msg'] = "Secret version not available."
                module.fail_json(**result)
            else:
                result['msg'] = destroy_secret_version(project_id=PROJECT_ID, secret_id=SECRET_NAME,
                                                        version_id=module.params['destroy_secret_version'])
                module.exit_json(**result)

        if module.params['name'] not in secrets_list:
            result['msg'] = create_secret(secret_name=SECRET_NAME, project_id=PROJECT_ID, secret_file_name=SECRET_FILE)
            module.exit_json(**result)
        else:
            result['msg'] = add_secret_version(secret_name=SECRET_NAME, project_id=PROJECT_ID, secret_file_name=SECRET_FILE)
            module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
