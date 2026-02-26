#!/usr/bin/python3

#
# tredictpy
#
# Copyright (c) 2025 Daniel Dean <dd@danieldean.uk>.
#
# Licensed under The MIT License a copy of which you should have
# received. If not, see:
#
# http://opensource.org/licenses/MIT
#

# API documentation: https://www.tredict.com/blog/oauth_docs/

import os
import requests
import uuid
import json
import time
from datetime import datetime, timezone
from typing import Self

import http.server
from socketserver import TCPServer

AUTH_URL = "https://www.tredict.com/authorization/"
TOKEN_URL = "https://www.tredict.com/user/oauth/v2/token/"
ENDPOINT_BASE_URL = "https://www.tredict.com/api/oauth/v2/"
ERROR_CODES = {
    200: "Request could be processed successfully",
    400: "The request is invalid or contains invalid data",
    401: "Invalid authorization header",
    403: "You provided an invalid access token. Maybe it is expired or it is out of scope",
    404: "Does not exist",
    429: "Too many requests.",
    500: "Something went wrong on our side",
    503: "Sorry, we went to the pub",
}
AUTH_CODE_EXPIRES_IN = 600
RENEWAL_BUFFER = 60


class APIException(Exception):
    """Simple exception to raise.

    Args:
        Exception (Object): Simple exception to raise.
    """

    pass


class TredictPy:
    """A straightforward script to authorise, authenticate and interact with Tredict."""

    def __init__(
        self,
        client_id: str = None,
        client_secret: str = None,
        token_append: str = None,
        endpoint_append: str = None,
        config_file: str = "tredict-secrets.json",
        with_personal_access_token: bool = True,
    ):
        """Initialise a new instance.

        Dot not use the constructor directly. Use one of the class methods instead.

        Args:
            client_id (str, optional): Client ID. Defaults to None.
            client_secret (str, optional): Client Secret. Defaults to None.
            token_append (str, optional): Token append string (secret). Defaults to None.
            endpoint_append (str, optional): Endpoint append string (secret). Defaults to None.
            config_file (str, optional): Path of the config file to load. Defaults to "tredict-secrets.json".
            with_personal_access_token (bool, optional): Authenticate using a personal access token or as an application.

        Raises:
            APIException: If the config does not contain all mandatory fields.
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_append = token_append
        self._endpoint_append = endpoint_append
        self._config_file = config_file
        self._with_personal_access_token = with_personal_access_token
        self._load_config()

    @classmethod
    def with_personal_access_token(
        self,
        config_file: str = "tredict-secrets.json",
    ) -> Self:
        """Initialise a new instance using a personal access token.

        Args:
            config_file (str, optional): Path of the config file to load. Defaults to "tredict-secrets.json".

        Raises:
            APIException: If the config does not contain all mandatory fields.
        """
        return TredictPy(None, None, None, None, config_file, True)

    @classmethod
    def as_application(
        self,
        client_id: str = None,
        client_secret: str = None,
        token_append: str = None,
        endpoint_append: str = None,
        config_file: str = "tredict-secrets.json",
    ) -> Self:
        """Initialise a new instance using application authentication.

        Args:
            client_id (str, optional): Client ID. Defaults to None.
            client_secret (str, optional): Client Secret. Defaults to None.
            token_append (str, optional): Token append string (secret). Defaults to None.
            endpoint_append (str, optional): Endpoint append string (secret). Defaults to None.
            config_file (str, optional): Path of the config file to load. Defaults to "tredict-secrets.json".

        Raises:
            APIException: If the config does not contain all mandatory fields.
        """
        return TredictPy(
            client_id, client_secret, token_append, endpoint_append, config_file, False
        )

    def _load_config(self) -> None:
        """Load the config from file.

        Raises:
            APIException: If the config does not contain all mandatory fields.
        """
        if os.path.isfile(self._config_file):
            with open(self._config_file, "rt") as f:
                self._config = json.load(f)
        else:
            self._config = {
                "auth_code": None,
                "user_access_token": None,
                "personal_access_token": None,
            }

        if not set(
            [
                "auth_code",
                "user_access_token",
                "personal_access_token",
            ]
        ).issubset(self._config.keys()):
            self._config_file = None
            self._config = None
            raise APIException("Config does not contain mandatory fields.")

    def _save_config(self, d: dict = None) -> None:
        """Save and optionally update the config to file.

        Args:
            d (dict, optional): Dict to add to the config. Defaults to None.
        """
        if d is not None:
            self._config.update(d)
        with open(self._config_file, "wt") as f:
            f.write(json.dumps(self._config, indent=4))

    @staticmethod
    def _params_from_path(path: str) -> dict:
        """Split a query string from a URL path and create a dict of the key and value parameter pairs.

        Args:
            path (str): URL path.

        Returns:
            dict: Dict of the key and value parameter pairs.
        """
        return dict(
            [tuple(p.split("=")) for p in path[(path.index("?") + 1) :].split("&")]
        )

    def _callback_server(self) -> dict:
        """Run a callback server to wait for the API authorisation response.

        Returns:
            dict: Response parameters.
        """

        done = False
        params = None

        class Handler(http.server.BaseHTTPRequestHandler):

            def do_GET(self):
                nonlocal done, params

                if self.path.startswith("/?code="):  # Successful callback

                    self.send_response(200, "Ok")
                    self.end_headers()

                    # Create a dict of the params, should be code and state
                    params = TredictPy._params_from_path(self.path)

                    self.wfile.write("Authorisation complete!".encode("utf-8"))
                    done = True

                elif self.path.startswith("/?error="):  # Error callback

                    self.send_response(200, "Ok")
                    self.end_headers()

                    # Create a dict of the params, should be code and state
                    params = TredictPy._params_from_path(self.path)

                    self.wfile.write("Authorisation failed!".encode("utf-8"))
                    done = True

                elif self.path.startswith("/favicon.ico"):  # Add favicon at some point
                    self.send_response(404, "Not Found")
                    self.end_headers()
                elif self.path.startswith("/privacy"):  # Will add a privacy policy
                    self.send_response(204, "No Content")
                    self.end_headers()
                else:  # A page that does not exist was requested
                    self.send_response(404, "Not Found")
                    self.end_headers()

        with TCPServer(("localhost", 8080), Handler) as httpd:
            print("Callback server started...")
            while not done:
                httpd.handle_request()
            print("Callback server stopped.")

        return params

    def _callback_headless(self) -> dict:
        """Prompt the user for the API authorisation response URL.

        For instances where a browser is not available on the same machine.

        Returns:
            dict: Response parameters.
        """
        return TredictPy._params_from_path(input("Paste the URL here: "))

    def is_authorised(self) -> bool:
        """Check if the client is authorised or not.

        Returns:
            bool: True if authorised and False if not.

        Raises:
            APIException: If a personal access token is being used.
        """

        if self._with_personal_access_token:
            raise APIException(
                "Cannot check validity when using a personal access token."
            )

        # First run, need to authorise and get an access token
        # Or was run before but did not complete authorisation
        if (
            not self._config["auth_code"]
            or not self._config["user_access_token"]
            or not self._config["personal_access_token"]
        ):
            return False
        else:
            return True

    def is_user_access_token_valid(self) -> bool:
        """Check if the user access token is valid.

        Returns:
            bool: True if the user access token is valid or False if not.

        Raises:
            APIException: If a personal access token is being used.
        """

        if self._with_personal_access_token:
            raise APIException(
                "Cannot check validity when using a personal access token."
            )

        # An access token was obtained before but it has expired
        # can refresh using the refresh token
        if (
            self._config["user_access_token"]
            and self._config["user_access_token"]["expires_on"]
            > int(time.time()) - RENEWAL_BUFFER
        ):
            return True
        else:
            return False

    def request_auth_code(self, headless: bool = False) -> None:
        """Request an authorisation code.

        Provides a link to authorise on Tredict then either starts a callback server to capture the response or awaits
        the URL to be entered for headless.

        Args:
            headless (bool, optional): Run in headless mode. Defaults to False.

        Raises:
            APIException: If the returned and supplied sates do not match or the authorisation failed or a personal
            access token is being used.
        """

        if self._with_personal_access_token:
            raise APIException(
                "Cannot request a authorisation code when using a personal access token."
            )

        user_uuid = str(uuid.uuid4())

        print(
            f"Open this URL to authorise: {AUTH_URL}?client_id={self._client_id}&state={user_uuid}"
        )

        # Start the callback server or go headless
        params = self._callback_headless() if headless else self._callback_server()

        if "code" in params.keys() and params["state"] == user_uuid:
            print("Authorisation complete!")
            self._save_config(
                {
                    "auth_code": params
                    | {"expires_on": int(time.time() + AUTH_CODE_EXPIRES_IN)}
                }
            )
        elif "code" in params.keys() and params["state"] != user_uuid:
            raise APIException(
                f"Authorisation failed! Returned state does not match supplied state."
            )
        else:  # If code is not in the keys authorisation failed
            raise APIException(
                f"Authorisation failed!\nCallback response:\n{json.dumps(params, indent=4)}"
            )

    def request_user_access_token(self, refresh: bool = False) -> None:
        """Request a user access token using either an authorisation code or a refresh token.

        Args:
            refresh (bool, optional): Set to True to use a long lived refresh token. Defaults to False.

        Raises:
            APIException: If there was an error requesting the user access token or a personal access token is being
            used.
        """

        if self._with_personal_access_token:
            raise APIException(
                "Cannot request a user access token when using a personal access token."
            )

        if not refresh and (
            self._config["auth_code"] is None or "auth_code" not in self._config.keys()
        ):
            raise APIException("You must request an authorisation code first.")

        if not refresh and self._config["auth_code"]["expires_on"] <= int(
            time.time() - RENEWAL_BUFFER
        ):
            raise APIException("Authorisation code has expired.")

        if refresh and not self._config["user_access_token"]:
            raise APIException(
                "You must request a user access token with an authorisation code before you can refresh."
            )

        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json;charset=UTF-8",
        }

        data = {
            "grant_type": "refresh_token" if refresh else "authorization_code",
            "code": None if refresh else self._config["auth_code"]["code"],
            "refresh_token": (
                self._config["user_access_token"]["refresh_token"] if refresh else None
            ),
        }

        r = requests.post(
            f"{TOKEN_URL}{self._token_append}",
            headers=headers,
            auth=(self._client_id, self._client_secret),
            data=data,
        )

        if r.status_code == 200:
            print("User access token successfully retrieved!")

            user_access_token = {
                "user_access_token": r.json()
                | {"expires_on": int(time.time() + r.json()["expires_in"])}
            }

            if refresh:
                user_access_token["user_access_token"].update(
                    {"refresh_token": data["refresh_token"]}
                )

            self._save_config(user_access_token)
        else:
            raise APIException(
                f"Retrieving user access token failed error {r.status_code} ({ERROR_CODES[r.status_code]})."
            )

    def deregister(self) -> None:
        """Deregister from the API.

        Raises:
            APIException: If there was an error deregistering or a personal access token is being used.
        """

        if self._with_personal_access_token:
            raise APIException("Cannot deregister when using a personal access token.")

        if not self.is_user_access_token_valid():
            raise APIException("User access token not obtained or expired.")

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
        }

        r = requests.delete(
            f"{TOKEN_URL}{self._token_append}",
            headers=headers,
        )

        if r.status_code == 200:
            print("Successfully deregistered!")
            self._save_config({"user_access_token": None, "auth_code": None})
        else:
            raise APIException(
                f"Deregistering failed error {r.status_code} ({ERROR_CODES[r.status_code]})."
            )

    def _list_endpoint(self, endpoint: str, params: dict) -> list:
        """Make a request to a list endpoint.

        Handles pagination.

        Args:
            endpoint (str): Name of the list endpoint.
            params (dict): Parameters as required by the endpoint.

        Raises:
            APIException: If the request fails.

        Returns:
            list: A list of the response pages.
        """

        if (
            not self._config["personal_access_token"]
            and not self.is_user_access_token_valid()
        ):
            raise APIException(
                "No personal access token and user access token not obtained or expired."
            )

        bearer_token = (
            self._config["personal_access_token"]
            or self._config["user_access_token"]["access_token"]
        )

        headers = {
            "authorization": f"bearer {bearer_token}",
            "accept": "application/json;charset=UTF-8",
        }

        pages = []
        url = (
            ENDPOINT_BASE_URL
            + endpoint
            + ("/" + self._endpoint_append if self._endpoint_append else "")
        )

        while True:

            r = requests.get(
                url,
                headers=headers,
                params=params,
            )

            if r.status_code == 200:
                pages.extend(
                    r.json()["_embedded"][list(r.json()["_embedded"].keys())[0]]
                )

                if (
                    "_links" not in r.json().keys()
                    or "next" not in r.json()["_links"].keys()
                ):
                    break
                else:
                    url = r.json()["_links"]["next"]["href"]
                    # Also need to set params to None as next contains params
                    params = None
            else:
                raise APIException(
                    f"Request to {endpoint} failed error {r.status_code} ({ERROR_CODES[r.status_code]})."
                )

        return pages

    def activity_list(self, start_date: datetime = None, page_size: int = 500) -> list:
        """Fetch a list of activities.

        Args:
            start_date (datetime, optional): Fetch activities starting from this date. Local times will be converted to
            UTC. Defaults to None.
            page_size (int, optional): Number of results per page, must be at least 50 and no more than 1000. Defaults
            to 500.

        Raises:
            APIException: If the page size requested is invalid or the request fails.

        Returns:
            list: A list of dicts containing the individual activities.
        """

        if page_size < 50 or page_size > 1000:
            raise APIException("Page size must be at least 50 and no more than 1000.")

        params = {
            "startDate": (
                start_date.astimezone(timezone.utc).isoformat() if start_date else None
            ),
            "pageSize": page_size,
        }

        return self._list_endpoint("activityList", params)

    def planned_training_list(
        self,
        start_date: datetime = None,
        end_date: datetime = None,
        sport_type: str = None,
    ) -> list:
        """Fetch a list of planned training.

        Args:
            start_date (datetime, optional): Fetch planned training starting from this date. Local times will be
            converted to UTC. Defaults to None.
            end_date (datetime, optional): Fetch planned training ending at this date. Local times will be converted to
            UTC. Defaults to None.
            sport_type (str, optional): Fetch planned training for only this sport. Possible values are 'running',
            'cycling', 'swimming', 'misc'. Default to None.

        Raises:
            APIException: If the request fails or the sport type specified is invalid.

        Returns:
            list: A list of dicts containing the individual activities.
        """

        if sport_type not in ["running", "cycling", "swimming", "misc"]:
            APIException(f"Invalid sport type '{sport_type}' specified!")

        params = {
            "startDate": (
                start_date.astimezone(timezone.utc).isoformat() if start_date else None
            ),
            "endDate": (
                end_date.astimezone(timezone.utc).isoformat() if end_date else None
            ),
            "sportType": sport_type,
        }

        return self._list_endpoint("plannedTrainingList", params)

    def _download_endpoint(
        self, endpoint: str, id: str = None, params: dict = None
    ) -> dict:
        """Make a request to a download endpoint (not a download file endpoint).

        Args:
            endpoint (str): Name of the list endpoint.
            id (str, optional): Optional ID, currently only applicable for activities. Defaults to None.
            params (dict, optional): Parameters if required for the request. Defaults to None.

        Raises:
            APIException: If the request fails.

        Returns:
            dict: A dict containing the response.
        """

        if (
            not self._config["personal_access_token"]
            and not self.is_user_access_token_valid()
        ):
            raise APIException(
                "No personal access token and user access token not obtained or expired."
            )

        bearer_token = (
            self._config["personal_access_token"]
            or self._config["user_access_token"]["access_token"]
        )

        headers = {
            "authorization": f"bearer {bearer_token}",
            "accept": "application/json;charset=UTF-8",
        }

        url = (
            ENDPOINT_BASE_URL
            + endpoint
            + ("/" + self._endpoint_append if self._endpoint_append else "")
        )
        url = f"{url}/{id}" if id else url  # Append the ID if there is one

        r = requests.get(
            url,
            headers=headers,
            params=params,
        )

        if r.status_code == 200:
            return r.json()

        else:
            raise APIException(
                f"Request to {endpoint} failed error {r.status_code} ({ERROR_CODES[r.status_code]})."
            )

    def activity_download(self, id: str) -> dict:
        """Download an activity as JSON.

        Args:
            id (str): ID of the activity. If unknown this can be found with activity_list().

        Raises:
            APIException: If the request fails.

        Returns:
            dict: A dict containing the activity.
        """
        return self._download_endpoint("activity", id=id)

    def bodyvalues_download(self) -> dict:
        """Download body values as JSON.

        Raises:
            APIException: If the request fails.

        Returns:
            dict: A dict containing the body values.
        """
        return self._download_endpoint("bodyvalues")

    def capacity_download(self, sport_type: str = None) -> dict:
        """Download capacity values as JSON.

        Params:
            sport_type (str, optional): Fetch planned training for only this sport. Possible values are 'running',
            'cycling', 'swimming', 'misc'. Default to None.

        Raises:
            APIException: If the request fails or the sport type is invalid.

        Returns:
            dict: A dict containing the capacity values.
        """

        if sport_type not in ["running", "cycling", "swimming", "misc"]:
            APIException(f"Invalid sport type '{sport_type}' specified!")

        params = {
            "sportType": sport_type,
        }

        return self._download_endpoint("capacity", params=params)

    def zones_download(self, sport_type: str = None) -> dict:
        """Download zones as JSON.

        Params:
            sport_type (str, optional): Fetch planned training for only this sport. Possible values are 'running',
            'cycling', 'swimming', 'misc'. Default to None.

        Raises:
            APIException: If the request fails or the sport type is invalid.

        Returns:
            dict: A dict containing the zones.
        """

        if sport_type not in ["running", "cycling", "swimming", "misc"]:
            APIException(f"Invalid sport type '{sport_type}' specified!")

        params = {
            "sportType": sport_type,
        }

        return self._download_endpoint("zones", params=params)

    def _file_download_endpoint(
        self, endpoint: str, id: str, params: dict = None, file_type: str = None
    ) -> bytes:
        """Make a request to a file download endpoint.

        Args:
            endpoint (str): Name of the list endpoint.
            id (str): ID for planned training or activity to download.
            params (dict, optional): Parameters if required for the request. Defaults to None.
            file_type (str, optional): Type of file to download, either 'json' or 'fit'. Only applicable to planned
            training. Defaults to None.

        Raises:
            APIException: If the request fails or the file type is invalid

        Returns:
            bytes: Binary content of the response which could be JSON or a FIT file.
        """

        if (
            not self._config["personal_access_token"]
            and not self.is_user_access_token_valid()
        ):
            raise APIException(
                "No personal access token and user access token not obtained or expired."
            )

        if file_type and (file_type not in ["json", "fit"] or endpoint == "activity"):
            APIException(
                f"Invalid file type '{file_type}' specified or file type not applicable!"
            )

        bearer_token = (
            self._config["personal_access_token"]
            or self._config["user_access_token"]["access_token"]
        )

        headers = {
            "authorization": f"bearer {bearer_token}",
            "accept": "application/json;charset=UTF-8",
        }

        url = (
            ENDPOINT_BASE_URL
            + endpoint
            + "/file"
            + ("/" + self._endpoint_append if self._endpoint_append else "")
        )
        url = (
            f"{url}/{file_type}" if file_type else url
        )  # Append the type if there is one
        url = f"{url}/{id}"

        r = requests.get(
            url,
            headers=headers,
            params=params,
        )

        if r.status_code == 200:
            return r.content
        else:
            raise APIException(
                f"Request to {endpoint} failed error {r.status_code} ({ERROR_CODES[r.status_code]})."
            )

    def planned_training_download(
        self, id: str, language: str = "en", extra_values: bool = False
    ) -> dict:
        """Download planned training as JSON.

        Params:
            id (str): ID of the planned training. If unknown this can be found with planned_training_list().
            language (str, optional): Use this language for the default workout name. Either 'en' or 'de'. Defaults to
            'en'.
            extra_values (bool, optional): Include extra values not in the Garmin specification. Extra value property
            names are: 'targetProgressionType', 'extraValueCadence', 'extraValueHeartrate', 'extraValueSpeed' and
            'extraValuePower'. Defaults to False.

        Raises:
            APIException: If the request fails or the language is invalid.

        Returns:
            dict: A dict containing the planned training.
        """

        if language not in ["en", "de"]:
            APIException(f"Invalid language '{language}' specified!")

        params = {"language": language, "extraValues": 1 if extra_values else 0}

        # This one is actually a file endpoint but returns JSON.
        return json.loads(
            self._file_download_endpoint(
                "plannedTraining", params=params, id=id, file_type="json"
            )
        )

    def planned_training_file_download(self, id: str) -> bytes:
        """Download planned training as a FIT file.

        Params:
            id (str): ID of the planned training. If unknown this can be found with planned_training_list().

        Raises:
            APIException: If the request fails.

        Returns:
            bytes: The fit file.
        """
        return self._file_download_endpoint("plannedTraining", id=id, file_type="fit")

    def activity_file_download(self, id: str) -> bytes:
        """Download an activity as a FIT file.

        Params:
            id (str): ID of the activity. If unknown this can be found with activity_list().

        Raises:
            APIException: If the request fails.

        Returns:
            bytes: The fit file.
        """
        return self._file_download_endpoint("activity", id=id)

    def activity_upload(
        self, file_path: str, activity_name: str = None, activity_notes: str = None
    ) -> dict:
        """Upload an activity as either a FIT or TCX activity file (FIT is preferred).

        Args:
            file_path (str): Path to the activity file.
            activity_name (str, optional): Name to use for the activity. Defaults to None.
            activity_notes (str, optional): Note to add to the activity. Defaults to None.

        Raises:
            APIException: If the request fails or the activity file is not of the correct type.

        Returns:
            dict: A dict containing either an on success (with ID of the upload) or on error response (with an ID if
            the failure is due to a duplicate).
        """

        if (
            not self._config["personal_access_token"]
            and not self.is_user_access_token_valid()
        ):
            raise APIException(
                "No personal access token and user access token not obtained or expired."
            )

        with open(file_path, "rb") as f:
            activity_file = f.read(12)

        if activity_file[8:12].decode() == ".FIT":
            file_type = ".fit"
        elif activity_file[0:5] == "<?xml":
            file_type = ".tcx"  # Probably - it is at least XML
        else:
            APIException(
                f"Unable to upload file as it is not a FIT or TCX activity file!"
            )

        bearer_token = (
            self._config["personal_access_token"]
            or self._config["user_access_token"]["access_token"]
        )

        headers = {
            "authorization": f"bearer {bearer_token}",
            "accept": "application/json;charset=UTF-8",
        }

        url = (
            ENDPOINT_BASE_URL
            + "activity/upload"
            + ("/" + self._endpoint_append if self._endpoint_append else "")
        )

        files = {
            "file": (
                file_path.split("/")[-1],
                open(file_path, "rb"),
            ),
            "name": (None, activity_name),
            "notes": (None, activity_notes),
        }

        # r = requests.Request("POST", url, headers=headers, files=files)
        # print(r.prepare().body.decode("unicode_escape"))
        # return

        r = requests.post(url, headers=headers, files=files)

        if r.status_code == 200:
            return r.json()
        else:
            # Handle the error codes correctly
            raise APIException(
                f"Activity file upload failed error {r.status_code} ({ERROR_CODES[r.status_code]})."
            )

    def bodyvalues_upload(
        self,
        values_date: datetime = datetime.now(timezone.utc),
        resting_heart_rate: int = None,
        weight: float = None,
        height: int = None,
        body_fat_percent: float = None,
        body_water_percent: float = None,
        body_muscle_percent: float = None,
    ):
        """Upload body values.

        Args:
            values_date (datetime, optional): Timestamp for the upload including timezone if applicable. Defaults to now
            in UTC.
            resting_heart_rate (int, optional): Value for resting heart rate (bpm). Defaults to None.
            weight (float, optional): Weight in kilograms. Defaults to None.
            height (fl0at, optional): height in centimetres. Defaults to None.
            body_fat_percent (float, optional): Body fat percentage. Defaults to None.
            body_water_percent (float, optional): Body water percentage. Defaults to None.
            body_muscle_percent (float, optional): Body muscle mass percentage. Defaults to None.

        Raises:
            APIException: If the request fails.
        """

        if (
            not self._config["personal_access_token"]
            and not self.is_user_access_token_valid()
        ):
            raise APIException(
                "No personal access token and user access token not obtained or expired."
            )

        bearer_token = (
            self._config["personal_access_token"]
            or self._config["user_access_token"]["access_token"]
        )

        headers = {
            "authorization": f"bearer {bearer_token}",
            "accept": "application/json;charset=UTF-8",
            "content-type": "application/json;charset=UTF-8",
        }

        url = (
            ENDPOINT_BASE_URL
            + "bodyvalues"
            + ("/" + self._endpoint_append if self._endpoint_append else "")
        )

        data = {
            "bodyvalues": [
                {
                    "timestamp": (values_date.astimezone(timezone.utc).isoformat()),
                    "timezoneOffsetInSeconds": int(
                        values_date.utcoffset().total_seconds()
                    ),
                    "restingHeartrate": resting_heart_rate,
                    "weightInKilograms": weight,
                    "bodyHeightInCentimeter": height,
                    "bodyFatInPercent": body_fat_percent,
                    "bodyWaterInPercent": body_water_percent,
                    "muscleMassInPercent": body_muscle_percent,
                }
            ],
        }

        # Delete the values not supplied
        for k, v in list(data["bodyvalues"][0].items()):
            if v is None:
                del data["bodyvalues"][0][k]

        r = requests.post(url, headers=headers, json=data)

        if r.status_code == 200:
            return  # Upload was successful but nothing is returned
        else:
            raise APIException(
                f"Body values upload failed error {r.status_code} ({ERROR_CODES[r.status_code]})."
            )
