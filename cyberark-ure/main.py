"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""CyberArk URE plugin."""


from typing import List, Dict, Optional

import os
import requests
import json
import datetime
import time
import re
import base64
import traceback

from urllib.parse import urlparse, parse_qs

from requests.models import HTTPError

from netskope.common.utils import add_user_agent

from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cre.models import (
    Record,
    ActionWithoutParams,
    Action,
)

PLATFORM_NAME= "CyberArk"
MODULE_NAME = "URE"
PLUGIN_VERSION = "1.0.0"
PLUGIN_NAME = "CyberArk URE Plugin"

class CyberArkPlugin(PluginBase):
    """CyberArk plugin implementation."""
    
    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def fetch_records(self) -> List[Record]:
        """Pull Records from CyberArk.

        Returns:
            List[Record]: List of records to be stored on the platform.
        """
        return []

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def fetch_scores(self, records: List[Record]) -> List[Record]:
        """Fetch user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        return []

    def _add_to_group(self, configuration: Dict, user_id: str, group_id: str):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on CyberArk.
        """
        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)
        url = "{base_url}/SaasManage/AddUsersAndGroupsToRole".format(
            base_url=f"{configuration['url'].strip().rstrip('/')}")
        body = {
              "Users": [
                user_id
              ],
              "Name": group_id
            }

        response = requests.post(url=url, data=body, headers=headers)
        response.raise_for_status()
        if response.status_code == 204:
            # We return because there is an empty JSON response
            # So it is successful and we do not need to anything
            # more after adding the member to group
            self.logger.info(
                f"{self.log_prefix}: Successfully added {logger_msg}."
            )
            return
        elif response.status_code == 400:
            resp_json = self.parse_response(response=response)
            api_err_msg = resp_json.get(
                "error", "No error details found in API response."
            )
            self.logger.warn(
                (
                    "{}: Unable to add {}. This error may occur if user "
                    "already exist in group. Error: {}".format(
                        self.log_prefix,
                        logger_msg,
                        str(api_err_msg),
                    )
                )
            )
            return

        self.handle_error(
            response, logger_msg
        )  # For capturing unexpected errors

    def _remove_from_group(
        self, configuration: Dict, user_id: str, group_id: str):
        """Remove specified user from the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            HTTPError: If the group does not exist on CyberArk.
        """
        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)
        url = "{base_url}/SaasManage/RemoveUsersAndGroupsFromRole".format(
            base_url=f"{configuration['url'].strip().rstrip('/')}")
        body = {
              "Users": [
                user_id
              ],
              "Name": group_id
            }

        response = requests.post(url=url, data=body, headers=headers)
        response.raise_for_status()
        if response.status_code == 204:
            self.logger.info(
                "{}: Successfully removed {}.".format(
                    self.log_prefix, logger_msg
                )
            )
            return

        elif response.status_code == 404:
            resp_json = self.parse_response(response=response)
            api_err_msg = resp_json.get(
                "error", "No error details found in API response."
            )
            err_msg = (
                "{}: Unable to remove {}. This error may occur if user does"
                " not exist in the group. Error: {}".format(
                    self.log_prefix,
                    logger_msg,
                    api_err_msg,
                )
            )
            self.logger.warn(err_msg)
            return


    def _get_all_groups(self, configuration: Dict) -> List:
        """Get list of all the groups.
        Args:
            configuration (Dict): Configuration parameters.
        Returns:
            List: List of all the groups.
        """
        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)
        url = "{base_url}/RedRock/query".format(base_url=f"{configuration['url'].strip().rstrip('/')}")
        body = "{'Script': 'Select ID, Name from Role order by Name'}"

        response = requests.post(url=url, data=body, headers=headers)
        groups = response.json()
        all_groups = []

        for group in groups["Result"]["Results"]:
            all_groups.append(group["Row"])

        return all_groups
        
    def _get_all_users(self, configuration: Dict) -> List:
        """Get list of all the users.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the users.
        """
        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)
        url = "{base_url}/RedRock/query".format(base_url=f"{configuration['url'].strip().rstrip('/')}")
        body = "{'Script': 'Select ID, Username from user order by Username'}"

        response = requests.post(url=url, data=body, headers=headers)
        users = response.json()
        all_users = []

        for user in users["Result"]["Results"]:
            all_users.append(user["Row"])

        return all_users


    def _find_user_by_username(self, configuration: Dict, username: str) -> Optional[Dict]:
        """Find user by username.

        Args:
            username (str): username to find.

        Returns:
            Optional[Dict]: User dictionary if found, None otherwise.
        """
        
        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)
        url = "{base_url}/RedRock/query".format(
            base_url=f"{configuration['url'].strip().rstrip('/')}")
            
        body = "{\"Script\": \"select ID, Username from Users where Username = '" + username + "'\"}"

        response = requests.post(url=url, data=body, headers=headers)
        users = response.json()
        all_users = []

        for user in users["Result"]["Results"]:
            all_users.append(user["Row"])
           
        return all_users

    def _find_group_by_name(self, configuration, name: str) -> Optional[Dict]:
        """Find group from list by name.

        Args:
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)
        url = "{base_url}/RedRock/query".format(
            base_url=f"{configuration['url'].strip().rstrip('/')}")
            
        body = "{\"Script\": \"select ID, Name from Role where Name = '" + name + "'\"}"

        response = requests.post(url=url, data=body, headers=headers)
        groups = response.json()
        all_groups = []

        for group in groups["Result"]["Results"]:
            all_groups.append(group["Row"])
           
        return all_groups

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def _create_group(self, configuration: Dict, name: str) -> Dict:
        """Create a new group with name.

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Name of the group to create.
            description (str): Group decription.

        Returns:
            Dict: Newly created group dictionary.
        """
        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)
        url = "{base_url}/Roles/StoreRole".format(
            base_url=f"{configuration['url'].strip().rstrip('/')}")
        body = {
              "Description": name,
              "Name": "Created From Netskop URE"
            }

        response = requests.post(url=url, data=body, headers=headers)
       
        if response["success"] == "false":
            raise HTTPError(
                f"Group could not be created in CyberArk."
            )
        response.raise_for_status()
        return response.json()

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user."""
        if action.value == "generate":
            pass
        user = record.uid
        users = self._get_all_users(self.configuration)
        match = self._find_user_by_username(self.configuration, user)
        if match is None:
            self.logger.warn(
                f"{PLUGIN_NAME}: User with email {user} not found on CyberArk."
            )
            return
        if action.value == "add":
            group_id = action.parameters.get("group")
            if group_id == "create":
                groups = self._get_all_groups(self.configuration)
                group_name = action.parameters.get("name").strip()
                match_group = self._find_group_by_name(self.configuration, group_name)
                if match_group is None:  # create group
                    group = self._create_group(self.configuration, group_name)
                    group_id = group["ID"]
                else:
                    group_id = match_group["ID"]
            self._add_to_group(self.configuration, match["ID"], group_id)
            self.logger.info(
                f"{PLUGIN_NAME}: Added {user} from group with ID {action.parameters.get('group')}."
            )
        elif action.value == "remove":
            self._remove_from_group(
                self.configuration, match["ID"], action.parameters.get("group")
            )
            self.logger.info(
                f"{PLUGIN_NAME}: Removed {user} from group with ID {action.parameters.get('group')}."
            )

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action."""
        if action.value == "generate":
            return []
        groups = self._get_all_groups(self.configuration)
        if action.value == "add":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["Name"], "value": str(g["ID"])} for g in groups
                    ]
                    + [{"key": "Create new group", "value": "create"}],
                    "default": str(groups[0]["ID"]),
                    "mandatory": True,
                    "description": "Select a group to add the user to.",
                },
                {
                    "label": "Group Name",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Create CyberArk group with given name if it does not exist.",
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Group",
                    "key": "group",
                    "type": "choice",
                    "choices": [
                        {"key": g["Name"], "value": str(g["ID"])} for g in groups
                    ],
                    "default": str(groups[0]["ID"]),
                    "mandatory": True,
                    "description": "Select a group to remove the user from.",
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate CyberArk action configuration."""
        if action.value not in ["add", "remove", "generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action.value == "generate":
            return ValidationResult(
                success=True, message="Validation successful."
            )
        groups = self._get_all_groups(self.configuration)
        if action.parameters.get("group") != "create" and not any(
            map(lambda g: g["id"] == action.parameters.get("group"), groups)
        ):
            return ValidationResult(
                success=False, message="Invalid group ID provided."
            )
        if (
            action.value == "add"
            and action.parameters.get("group") == "create"
            and len(action.parameters.get("name", "").strip()) == 0
        ):
            return ValidationResult(
                success=False, message="Group Name can not be empty."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL."""
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_auth(self, configuration):
        """Validate CyberArk credentials."""

        headers = CyberArkPlugin.get_protected_cyberark_headers(self, configuration)

        self.logger.error(
            "Plugin check" + str(headers)
        )

        url = "{base_url}/UserMgmt/GetUserInfo".format(
            base_url=f"{configuration['url'].strip().rstrip('/')}")

        try:
            response = requests.post(url=url,headers=headers, data="")
            response.raise_for_status()
            if response.status_code in [200, 201]:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
        except Exception as err:
            self.logger.error(
                f"{PLUGIN_NAME}: Error occured while authentication. {err}"
            )
        return ValidationResult(
            success=False,
            message="Invalid CyberArk Credentials or URL. Please Check logs.",
        )

    def validate_cyberark_domain(self, url: str):
        """Validate Cyberark domain."""
        valid_domains = [".idaptive.com", ".cyberark.cloud"]
        for domain in valid_domains:
            if domain in url:
                return True
        return False

    def validate(self, configuration: Dict):
        """Validate CyberArk configuration."""

        if (
            "url" not in configuration
            or not configuration["url"].strip()
            or not self._validate_url(configuration["url"])
            or not self.validate_cyberark_domain(configuration["url"].strip())
        ):
            self.logger.error(f"{PLUGIN_NAME}: Invalid CyberArk domain provided.")
            return ValidationResult(
                success=False, message="Invalid CyberArk domain provided."
            )

        if (
            "service_user" not in configuration
            or not configuration["service_user"].strip()
        ):
            self.logger.error(f"{PLUGIN_NAME}: Service User should not be empty.")
            return ValidationResult(
                success=False,
                message="Service User should not be empty.",
            )
            
        if (
            "service_password" not in configuration
            or not configuration["service_password"].strip()
        ):
            self.logger.error(f"{PLUGIN_NAME}: Service Password should not be empty.")
            return ValidationResult(
                success=False,
                message="Service Password should not be empty.",
            )

        return self._validate_auth(configuration)
        
    @staticmethod  
    def get_protected_cyberark_headers(self, configuration: Dict):
        cyberark_service_user = str({configuration["service_user"]}).strip("{'").strip("'}")
        cyberark_service_password = str({configuration["service_password"]}).strip("{'").strip("'}")
        url = f"{configuration['url'].strip().rstrip('/')}" + "/oauth2/token/ciamapisvc"
        body = "grant_type=client_credentials&scope=all"
        cyberark_oauth_headers = {
    		"Accept": "application/json",
    		"Content-Type": "application/x-www-form-urlencoded",
    	}
        cyberark_oauth_headers["Authorization"] = "Basic {0}".format(CyberArkPlugin.get_encoded_auth(cyberark_service_user, cyberark_service_password))
        rest_response = requests.post(url=url, headers=cyberark_oauth_headers, data=body)
        bearer_response = rest_response.json()
        cyberark_protected_headers = {
    		"Authorization": "Bearer {0}".format(bearer_response["access_token"])
    		}
        return cyberark_protected_headers
        
    @staticmethod  
    def get_encoded_auth(client_id, client_secret):
    	auth_raw = "{client_id}:{client_secret}".format(client_id=client_id,client_secret=client_secret)
    	encoded_auth = base64.b64encode(bytes(auth_raw, 'UTF-8')).decode("UTF-8")
    	return encoded_auth
