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

    def __init__(self):
        """Initialise a new instance."""
        self._config = None

    def load_config(self) -> None:
        """Load the config from file."""
        with open("./config.json", "rt") as f:
            self._config = json.loads(f.read())

    def save_config(self, d: dict = None) -> None:
        """Save and optionally update the config to file.

        Args:
            d (dict, optional): Dict to add to the config. Defaults to None.
        """
        if d is not None:
            self._config.update(d)
        with open("./config.json", "wt") as f:
            f.write(json.dumps(self._config, indent=4))

    @staticmethod
    def params_from_path(path: str) -> dict:
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
                    params = TredictPy.params_from_path(self.path)

                    self.wfile.write("Authorisation complete!".encode("utf-8"))
                    done = True

                elif self.path.startswith("/?error="):  # Error callback

                    self.send_response(200, "Ok")
                    self.end_headers()

                    # Create a dict of the params, should be code and state
                    params = TredictPy.params_from_path(self.path)

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
        return TredictPy.params_from_path(input("Paste the URL here: "))

    def request_auth_code(self, headless: bool = False) -> None:
        """Request an authorisation code.

        Provides a link to authorise on Tredict then either starts a callback server to capture the response or awaits
        the URL to be entered for headless.

        Args:
            headless (bool, optional): _description_. Defaults to False.

        Raises:
            APIException: _description_
        """

        user_uuid = str(uuid.uuid4())

        print(
            f"Open this URL to authorise: {self._config['auth_url']}?client_id={self._config['client_id']}&state={user_uuid}"
        )

        # Start the callback server or go headless
        params = self._callback_headless() if headless else self._callback_server()

        if "code" in params.keys():
            print(
                "Authorisation complete!",
                "Callback response:",
                json.dumps(params, indent=4),
                sep="\n",
            )
            self.save_config({"auth_code": params})
        else:  # If code is not in the keys authorisation failed
            print(
                "Authorisation failed!",
                "Callback response:",
                json.dumps(params, indent=4),
                sep="\n",
            )
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
            print(
                "User access token successfully retrieved!",
                json.dumps(r.json(), indent=4),
                sep="\n",
            )

            user_access_token = {
                "user_access_token": r.json()
                | {"expires_on": int(time.time() + r.json()["expires_in"])}
            }

            if refresh:
                user_access_token["user_access_token"].update(
                    {"refresh_token": data["refresh_token"]}
                )

            self.save_config(user_access_token)
        else:
            # Handle the error codes correctly
            print(
                f"Retrieving User access token failed error {r.status_code} ({r.url})."
            )
            raise APIException(
                f"Retrieving user access token failed error {r.status_code} ({r.url})."
            )

    def deregister(self) -> None:
        """Deregister from the API.

        Raises:
            APIException: If there was an error deregistering.
        """

        headers = {
            "authorization": f"bearer {self._config['user_access_token']['access_token']}",
        }

        r = requests.delete(
            f"{self._config['token_url']}{self._config['token_append']}",
            headers=headers,
        )

        if r.status_code == 200:
            print("Successfully deregistered!")
            self.save_config({"user_access_token": None, "auth_code": None})
        else:
            # Handle the error codes correctly
            print(f"Deregistering failed error {r.status_code} ({r.url}).")
            raise APIException(f"Deregistering failed error {r.status_code} ({r.url}).")

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
                pages.append(r.json())

                if "next" not in r.json()["_links"].keys():
                    break
                else:
                    url = r.json()["_links"]["next"]
                    # Also need to set params to None as next contains params
                    params = None
            else:
                # Handle the error codes correctly
                print(f"Request to {endpoint} failed error {r.status_code}. ({r.url}).")
                raise APIException(
                    f"Request to {endpoint} failed error {r.status_code}. ({r.url})."
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
            "startDate": start_date.astimezone(timezone.utc).isoformat(),
            "pageSize": page_size,
        }

        # Tidy pages to leave just an activity list

        return self._list_endpoint("activityList", params)
