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

import requests
import uuid
import json
import time
from datetime import datetime, timezone

import http.server
from socketserver import TCPServer


class APIException(Exception):
    """Simple exception to raise.

    Args:
        Exception (Object): Simple exception to raise.
    """

    pass


class TredictPy:
    """A straightforward script to authorise, authenticate and interact with Tredict."""

    def __init__(self, config_file: str = "tredict-config.json"):
        """Initialise a new instance.

        Args:
            config_file (str, optional): Path of the config file to load. Defaults to "tredict-config.json".

        Raises:
            APIException: If the config does not contain all mandatory fields.
        """
        self._load_config(config_file=config_file)

    def _load_config(self, config_file: str = "tredict-config.json") -> None:
        """Load the config from file.

        Args:
            config_file (str, optional): Path of the config file to load. Defaults to "tredict-config.json".

        Raises:
            APIException: If the config does not contain all mandatory fields.
        """
        self._config_file = config_file
        with open(self._config_file, "rt") as f:
            self._config = json.loads(f.read())

        if not set(
            [
                "auth_url",
                "token_url",
                "token_append",
                "endpoint_base_url",
                "endpoint_append",
                "service_id",
                "client_id",
                "client_secret",
                "auth_code_expires_in",
                "renewal_buffer",
                "error_codes",
            ]
        ).issubset(self._config.keys()):
            self._config_file = None
            self._config = None
            raise APIException(
                "Config does not contain mandatory fields. Check example."
            )

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

    def request_auth_code(self, headless: bool = False) -> None:
        """Request an authorisation code.

        Provides a link to authorise on Tredict then either starts a callback server to capture the response or awaits
        the URL to be entered for headless.

        Args:
            headless (bool, optional): Run in headless mode. Defaults to False.

        Raises:
            APIException: If the returned and supplied sates do not match or the authorisation failed.
        """

        user_uuid = str(uuid.uuid4())

        print(
            f"Open this URL to authorise: {self._config['auth_url']}?client_id={self._config['client_id']}&state={user_uuid}"
        )

        # Start the callback server or go headless
        params = self._callback_headless() if headless else self._callback_server()

        if "code" in params.keys() and params["state"] == user_uuid:
            print("Authorisation complete!")
            self._save_config({"auth_code": params})
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
            APIException: If there was an error requesting the user access token.
        """

        if not refresh and (
            self._config["auth_code"] is None or "auth_code" not in self._config.keys()
        ):
            raise APIException("You must request an authorisation code first.")

        if refresh and (
            self._config["user_access_token"] is None
            or "user_access_token" not in self._config.keys()
        ):
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
            f"{self._config['token_url']}{self._config['token_append']}",
            headers=headers,
            auth=(self._config["client_id"], self._config["client_secret"]),
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
                f"Retrieving user access token failed error {r.status_code} ({self._config['error_codes'][str(r.status_code)]})."
            )

    def deregister(self) -> None:
        """Deregister from the API.

        Raises:
            APIException: If there was an error deregistering.
        """

        if (
            self._config["user_access_token"] is None
            or "user_access_token" not in self._config.keys()
        ):
            raise APIException("You must request a user access token first.")

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
        }

        r = requests.delete(
            f"{self._config['token_url']}{self._config['token_append']}",
            headers=headers,
        )

        if r.status_code == 200:
            print("Successfully deregistered!")
            self._save_config({"user_access_token": None, "auth_code": None})
        else:
            raise APIException(
                f"Deregistering failed error {r.status_code} ({self._config['error_codes'][str(r.status_code)]})."
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
            self._config["user_access_token"] is None
            or "user_access_token" not in self._config.keys()
        ):
            raise APIException("You must request a user access token first.")

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
            "accept": "application/json;charset=UTF-8",
        }

        pages = []
        url = f"{self._config['endpoint_base_url']}{endpoint}/{self._config['endpoint_append']}"

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
                    url = r.json()["_links"]["next"]
                    # Also need to set params to None as next contains params
                    params = None
            else:
                raise APIException(
                    f"Request to {endpoint} failed error {r.status_code} ({self._config['error_codes'][str(r.status_code)]})."
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
            self._config["user_access_token"] is None
            or "user_access_token" not in self._config.keys()
        ):
            raise APIException("You must request a user access token first.")

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
            "accept": "application/json;charset=UTF-8",
        }

        url = f"{self._config['endpoint_base_url']}{endpoint}/{self._config['endpoint_append']}"
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
                f"Request to {endpoint} failed error {r.status_code} ({self._config['error_codes'][str(r.status_code)]})."
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
            self._config["user_access_token"] is None
            or "user_access_token" not in self._config.keys()
        ):
            raise APIException("You must request a user access token first.")

        if file_type and (file_type not in ["json", "fit"] or endpoint == "activity"):
            APIException(
                f"Invalid file type '{file_type}' specified or file type not applicable!"
            )

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
            "accept": "application/json;charset=UTF-8",
        }

        url = f"{self._config['endpoint_base_url']}{endpoint}/file/{self._config['endpoint_append']}"
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
                f"Request to {endpoint} failed error {r.status_code} ({self._config['error_codes'][str(r.status_code)]})."
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
            self._config["user_access_token"] is None
            or "user_access_token" not in self._config.keys()
        ):
            raise APIException("You must request a user access token first.")

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

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
            "accept": "application/json;charset=UTF-8",
        }

        url = f"{self._config['endpoint_base_url']}activity/upload/{self._config['endpoint_append']}"

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
                f"Activity file upload failed error {r.status_code} ({self._config['error_codes'][str(r.status_code)]})."
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
            self._config["user_access_token"] is None
            or "user_access_token" not in self._config.keys()
        ):
            raise APIException("You must request a user access token first.")

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
            "accept": "application/json;charset=UTF-8",
            "content-type": "application/json;charset=UTF-8",
        }

        url = f"{self._config['endpoint_base_url']}bodyvalues/{self._config['endpoint_append']}"

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
                f"Body values upload failed error {r.status_code} ({self._config['error_codes'][str(r.status_code)]})."
            )
