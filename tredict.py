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

import http.server
from socketserver import TCPServer


class APIException(Exception):
    pass


config = None


def load_config() -> None:
    global config
    with open("./config.json", "rt") as f:
        config = json.loads(f.read())


def save_config(d: dict = None) -> None:
    if d is not None:
        config.update(d)
    with open("./config.json", "wt") as f:
        f.write(json.dumps(config, indent=4))


def params_from_path(path: str) -> dict:
    """Split a query string from a URL path and create a dict of the key and value parameter pairs.

    Args:
        path (str): URL path.

    Returns:
        dict: Dict of the key and value parameter pairs.
    """
    return dict([tuple(p.split("=")) for p in path[(path.index("?") + 1) :].split("&")])


def callback_server() -> dict:
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
                params = params_from_path(self.path)

                self.wfile.write("Authorisation complete!".encode("utf-8"))
                done = True

            elif self.path.startswith("/?error="):  # Error callback

                self.send_response(200, "Ok")
                self.end_headers()

                # Create a dict of the params, should be code and state
                params = params_from_path(self.path)

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


def callback_headless() -> dict:
    """Prompt the user for the API authorisation response URL.

    For instances where a browser is not available on the same machine.

    Returns:
        dict: Response parameters.
    """
    return params_from_path(input("Paste the URL here: "))


def request_auth_code(headless: bool = False) -> None:

    user_uuid = str(uuid.uuid4())

    print(
        f"Open this URL to authorise: {config['auth_url']}?client_id={config['client_id']}&state={user_uuid}"
    )

    # Start the callback server or go headless
    params = callback_headless() if headless else callback_server()

    if "code" in params.keys():
        print(
            "Authorisation complete!",
            "Callback response:",
            json.dumps(params, indent=4),
            sep="\n",
        )
        save_config({"auth_code": params})
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


def request_user_access_token() -> None:

    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "application/json;charset=UTF-8",
    }

    data = {
        "grant_type": "authorization_code",  # "refresh_token",
        "code": config["auth_code"]["code"],
        # "refresh_token": None,
    }

    r = requests.post(
        f"{config['token_url']}{config['token_append']}",
        headers=headers,
        auth=(config["client_id"], config["client_secret"]),
        data=data,
    )

    if r.status_code == 200:
        print(
            "User access token successfully retrieved!",
            json.dumps(r.json(), indent=4),
            sep="\n",
        )
        save_config(
            {
                "user_access_token": r.json()
                | {"expires_on": int(time.time() + r.json()["expires_in"])}
            }
        )
    else:
        # Handle the error codes correctly
        print(f"Retrieving User access token failed error {r.status_code} ({r.url}).")
        raise APIException(
            f"Retrieving user access token failed error {r.status_code} ({r.url})."
        )


def deregister() -> None:

    headers = {
        "authorization": f"bearer {config['user_access_token']['access_token']}",
    }

    r = requests.delete(
        f"{config['token_url']}{config['token_append']}", headers=headers
    )

    if r.status_code == 200:
        print("Successfully deregistered!")
        save_config({"user_access_token": None, "auth_code": None})
    else:
        # Handle the error codes correctly
        print(f"Deregistering failed error {r.status_code} ({r.url}).")
        raise APIException(f"Deregistering failed error {r.status_code} ({r.url}).")


load_config()

request_auth_code()

request_user_access_token()

input("Press enter to deregister...")

deregister()
