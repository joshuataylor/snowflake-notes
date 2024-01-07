# Basic example implementation of logging into Snowsight using Username/Password, SSO and Duo (with passcode).
#
# This script should work with Python 3.5+ without needing additional libraries.
#
# Usage: python3 snowsight_basic.py -m METHOD -a ACCOUNT_IDENTIFIER -u LOGIN_NAME [-p PASSWORD] [-l {DEBUG,INFO}]
#
# Password is optional unless using password login method.
#
# Login methods (-m):
# password - Login using username and password.
# sso - Login using federated authentication/SSO
# duo_passcode - Login using Duo Passcode
# duo - Login using Duo (todo!)
#
# Log level can be either debug or info, defaults to info. Debug shows verbose request/response information.

import argparse
import datetime
import http.cookiejar
import json
import logging
import socket
import sys
import urllib.request
import urllib.error
from typing import Optional


def validate_snowflake_url(account_identifier: str) -> dict:
    """
    Validates a Snowflake account using the account identifier,
    and returns the account name, region and app server URL as a dict.

    Args:
        account_identifier:
            Snowflake account identifier, it's usually `https://<account_identifier>.snowflakecomputing.com`.
            Most of the time it is `<USERNAME>.<ACCOUNT_NAME>`.

    Returns:
        dict with the response from the Snowflake API

    """
    url = f"https://app.snowflake.com/v0/validate-snowflake-url?url={account_identifier}&isSecondaryAccount=false"
    logging.debug("Validating account_identifier - %s", account_identifier)

    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0"
        },
    )

    # Perform the request and extracts the account name, region and app server URL.
    try:
        with urllib.request.urlopen(req) as response:
            response_data = json.loads(response.read().decode())
            logging.debug("login_request response - %s", response_data)

            # region - the region of the snowflake account (us-east-1, etc.)
            # instance_url - The URL to the users instance, usually `https://<ACCOUNT_NAME>.<REGION>.snowflakecomputing.com`
            # app_server_url - the snowsight API URL, `https://apps-api.c1.<REGION>.aws.app.snowflake.com`

            return {
                "account": response_data["account"],
                "region": response_data["region"],
                "instance_url": response_data["url"],
                "app_server_url": response_data["appServerUrl"],
                "valid": response_data["valid"],
            }

    except urllib.error.URLError as e:
        logging.info(e.reason)


def login_request(base_url: str, login_payload: dict) -> dict:
    """
    Performs the login-request against Snowflake, using the payload from the authentication method.

    Each authentication method has a different login payload that must be sent.

    Args:
        base_url: The base URL to authenticate to
        login_payload: The login payload, a Python dict.

    Returns: A dict containing the redirect_uri and the name for the header.

    """
    # Convert the data to JSON
    data_json = json.dumps(login_payload).encode("utf-8")
    # Headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    }

    # Create a connection - replace with proxy details if needed
    url = f"{base_url}/session/v1/login-request?__uiAppName=Login"

    req = urllib.request.Request(url, data=data_json, headers=headers, method="POST")

    # Perform the request and extract the 'redirectURI' and userName
    try:
        with urllib.request.urlopen(req) as response:
            response_data = json.loads(response.read().decode())
            logging.debug("login_request response - %s", response_data)

            if response_data.get("success") is False:
                return_message = "Authentication Failed - "
                # is there a code?
                if response_data.get("code"):
                    return_message += response_data["code"] + " - "

                # is there a message?
                if response_data.get("message"):
                    return_message += response_data["message"] + " - "

                # raise
                raise Exception(return_message)

            return {
                "redirect_uri": response_data["data"]["redirectURI"],
                "name": response_data["data"]["authnEvent"]["userName"],
            }

    except urllib.error.URLError as e:
        logging.info(e.reason)


def login_username_password_payload(account_name: str, login_name: str, password: str) -> dict:
    """
    The simplest way a user can log in is via username and password, as Snowflake directly returns the redirectUri.

    Args:
        account_name: The Snowflake account name, without the region.
        login_name: The login name to authenticate with.
        password: The password to authenticate with.

    Returns:
        Dict of token, proof_key - proof key is used in the final step.
    """

    return {
        "data": {
            "ACCOUNT_NAME": account_name,
            "LOGIN_NAME": login_name,
            "PASSWORD": password,
            "CLIENT_APP_ID": "Snowflake UI",
            "CLIENT_APP_VERSION": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
        }
    }


def login_duo_passcode_payload(
    instance_url: str, account_name: str, login_name: str, password: str, passcode: str
) -> dict:
    """
    To log into Snowsight using Duo Passcode, the user must provide a Pass Code from the Duo app,
    then pass it in the login request.

    This is a two-step process:
        1. POST login-request with the acount name, login name, password and passcode - this returns an inFlightCtx
        2. POST login-request again, with the inFlightCtx from the first request in the body

    Args:
        instance_url: The instance url, from validate-url
        account_name: The Snowflake account name, without the region.
        login_name: The login_name to authenticate with.
        password: The password to authenticate with.
        passcode: The passcode from the Duo app

    Returns:
        Dict of token, proof_key - proof key is used in the final step.
    """

    duo_passcode_login_payload = {
        "data": {
            "ACCOUNT_NAME": account_name,
            "LOGIN_NAME": login_name,
            "PASSWORD": password,
            "CLIENT_APP_ID": "Snowflake UI",
            "CLIENT_APP_VERSION": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
            "EXT_AUTHN_DUO_METHOD": "passcode",
            "PASSCODE": passcode,
        }
    }

    # Convert the data to JSON
    data_json = json.dumps(duo_passcode_login_payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    }

    url = f"{instance_url}/session/v1/login-request?__uiAppName=Login"

    req = urllib.request.Request(url, data=data_json, headers=headers, method="POST")

    # Perform the request and extract the 'inFlightCtx'
    try:
        with urllib.request.urlopen(req) as response:
            response_data = json.loads(response.read().decode())
            logging.debug("login_request response - %s", response_data)

            # Duo seems to give success false all the time..
            # So we need to also check the message `Duo Security authentication is successful.`
            if (
                response_data.get("success") is False
                and response_data["message"]
                != "Duo Security authentication is successful."
            ):
                return_message = "Authentication Failed - "
                # is there a code?
                if response_data.get("code"):
                    return_message += response_data["code"] + " - "

                # is there a message?
                if response_data.get("message"):
                    return_message += response_data["message"] + " - "

                # raise
                raise Exception(return_message)

            inflight_ctx: str = response_data["data"]["inFlightCtx"]

            return {
                "data": {
                    "CLIENT_APP_ID": "Snowflake UI",
                    "CLIENT_APP_VERSION": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
                },
                "inFlightCtx": inflight_ctx,
            }

    except urllib.error.URLError as e:
        logging.info(e.reason)


def login_sso_payload(instance_url: str, account_name: str, login_name: str) -> dict:
    """
    Starts the authentication flow, where the user will need to authenticate via their Web Browser with their IdP,
    which they are then redirected back to localhost, so we can retrieve their token.

    This is a large function, to demonstrate the flow.

    Please split this up into smaller "byte-sized" functions in production code! :-)

    Args:
        instance_url: The instance_url returned from validate-url
        account_name: The Snowflake account name, without the region.
        login_name: The login name to authenticate with, this must be the LOGIN_NAME of the user in Snowflake,
                  and the email address of the user in the IdP.

    Returns:
        Dict of token, proof_key - proof key is used in the final step.
    """

    # First, we need to listen on localhost:{PORT} for the redirect from the IdP. The port doesn't
    # really matter, we can try and bind on a dynamic port.
    # Create a socket and bind to a random port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 0))

    # Accept connections, we don't care about backlog.
    server_socket.listen(0)

    # The callback port is needed, as we need to pass it to Snowflake in the login request (BROWSER_MODE_REDIRECT_PORT).
    callback_port = server_socket.getsockname()[1]
    logging.debug("Listening on http://localhost:%s", callback_port)

    data = {
        "data": {
            "CLIENT_APP_ID": "Snowflake UI",
            "CLIENT_APP_VERSION": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
            "ACCOUNT_NAME": account_name.upper(),
            "LOGIN_NAME": login_name,
            "AUTHENTICATOR": "EXTERNALBROWSER",
            "BROWSER_MODE_REDIRECT_PORT": str(callback_port),
        }
    }

    data_json = json.dumps(data).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    }

    url = f"{instance_url}/session/authenticator-request?__uiAppName=Login"

    logging.debug("SSO Login URL (POST) - %s", url)
    logging.debug("SSO Login Data - %s", data)

    req = urllib.request.Request(url, data=data_json, headers=headers, method="POST")

    # Perform the request and extract the 'redirectURI'
    try:
        with urllib.request.urlopen(req) as initial_response:
            initial_response_data = json.loads(initial_response.read().decode())
            logging.debug(initial_response_data)

            # SSO URL is the URL to redirect the user to, so they can authenticate with their IdP.
            # print this for the user to open it in their browser, as the default browser might be wrong.
            sso_url = initial_response_data["data"]["ssoUrl"]

            # The proof key is used to verify the response from the IdP, we need to store this for later.
            proof_key = initial_response_data["data"]["proofKey"]
            logging.debug("Proof key - %s", proof_key)

            print(
                "Please open the following URL in your browser and authenticate with your IdP."
            )
            print(sso_url)

            # This snippet has been shamelessly borrowed from Snowflakes Python connector, as it's a nice way to handle
            # the redirect from the IdP.
            # [See webbrowser.py](https://github.com/snowflakedb/snowflake-connector-python/blob/main/src/snowflake/connector/auth/webbrowser.py#L117)
            logging.debug("Waiting for redirect from IdP..")

            token = token_socket_listener(server_socket)
            logging.debug("token - %s", token)

            return {
                "data": {
                    "CLIENT_APP_ID": "Snowflake UI",
                    "CLIENT_APP_VERSION": datetime.datetime.now().strftime(
                        "%Y%m%d%H%M%S"
                    ),
                    "ACCOUNT_NAME": account_name,
                    "LOGIN_NAME": login_name,
                    "AUTHENTICATOR": "EXTERNALBROWSER",
                    "TOKEN": token,
                    "PROOF_KEY": proof_key,
                }
            }

    except urllib.error.URLError as e:
        logging.debug(e.reason)


def token_socket_listener(server_socket: socket):
    # This needs to be in a function so when we have the token we can "return".

    while True:
        socket_client, _ = server_socket.accept()
        try:
            data = socket_client.recv(16384).decode("utf-8").split("\r\n")
            logging.debug("Received data: %s", data)
            # This returns as a list, as it's chunked.
            # So we can just loop
            logging.debug("Finding token..")
            for line in data:
                logging.debug("Line: %s", line)
                if line.startswith("GET /?token="):
                    token = line.split(" ")[1].split("=")[1]
                    logging.info("found token? %s", token)
                    return token
        finally:
            socket_client.shutdown(socket.SHUT_RDWR)
            socket_client.close()


def complete_oauth(redirect_uri: str, account_name: str, region: str) -> str:
    """
    Completes the OAuth flow, returning the cookies as a string that can be used to authenticate with Snowsight.

    We need to get the `S8_SESSION_` and `user-` cookies for future requests.

    Args:
        redirect_uri: The redirect URL returned from the login request
        account_name: The Snowflake account name
        region: The Snowflake region (us-east-1, etc.)

    Returns:
        Cookies, as a string, to use for authentication in Snowsight, prefixed as `S8_SESSION_` and `user-`.
    """

    # Create a cookie jar to handle cookies, as Pythons urllib doesn't handle multiple headers
    # with the same name well.
    cookie_jar = http.cookiejar.CookieJar()

    # Create an opener that will use the cookie jar
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    url = f"{redirect_uri}&state=%7B%22url%22%3A%22https%3A%2F%2F{account_name}.{region}.snowflakecomputing.com%22%7D"

    # Open the URL, we don't care about the response, we just want the cookies.
    opener.open(url)

    # Extract cookies from the cookie jar
    cookies = []

    # Display the extracted cookies
    for cookie in [cookie for cookie in cookie_jar]:
        cookies.append(cookie.name + "=" + cookie.value.replace('"', ""))

    return "; ".join(cookies)


def snowsight_bootstrap(
    app_server_url: str,
    account_name: str,
    region: str,
    name: Optional[str] = None,
    cookies: Optional[str] = None,
) -> dict:
    """
    Snowflake requires an `OrganizationID` and `csrfToken` for Snowsight endpoints, which you can retrieve
    from the `bootstrap` endpoint.

    Args:
        app_server_url: The app server URL from validate-url
        account_name: The Snowflake account name
        region: The Snowflake region (us-east-1, etc.)
        name: The name is different to the login_name, the login_name is used for SSO and might be an email,
              whereas the name might just be a string. `SHOW USERS` displays the name and the login_name.
              The name is returned in the login-request
        cookies: The list of cookies to use for authentication
    Returns:
        A dict containing the `OrganizationID` and `csrfToken` for the Snowflake account.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    }

    if name is not None:
        headers[
            "X-Snowflake-Context"
        ] = f"{name.upper()}::https://{account_name}.{region}.snowflakecomputing.com"

    if cookies is not None:
        headers["Cookie"] = cookies

    # Create a connection - replace with proxy details if needed
    url = f"{app_server_url}/bootstrap"

    req = urllib.request.Request(url, headers=headers, method="GET")

    # Perform the request and extract the 'redirectURI'
    try:
        with urllib.request.urlopen(req) as response:
            response_data = json.loads(response.read().decode())
            csrf_token = response_data["PageParams"]["csrfToken"]
            org_id = None

            # Unauthenticated responses don't have the org (as they don't have a user, as they're not logged in)
            if response_data.get("User", None) is None:
                return {"csrf_token": csrf_token, "org_id": org_id}

            # `OrganizationID` is from either:
            #
            # 1. response_data["Org"]["id"].
            # 2. That value can be null/empty, fall back to response_data["User"]["defaultOrgId"]
            org_id = response_data.get("Org", {}).get("id", None) or response_data["User"].get("defaultOrgId", None)

            return {"csrf_token": csrf_token, "org_id": org_id}

    except urllib.error.URLError as e:
        logging.info(e.reason)


def snowsight_entities(
    app_server_url: str,
    account_name: str,
    region: str,
    name: str,
    org_id: str,
    csrf_token: str,
    cookies: str,
) -> list:
    """
    Returns a list of worksheets for a Snowflake account.

    This example does not perform pagination, so if you have more than 500 worksheets, you will need to
    implement that yourself.

    Args:
        app_server_url: The app server URL from validate-url
        account_name: The Snowflake account name
        region: The Snowflake region (us-east-1, etc.)
        name: The name to use
        org_id: The OrganizationID to use
        csrf_token: The csrfToken to use
        cookies: The list of cookies to use for authentication

    Returns:
        A dict containing the `OrganizationID` and `csrfToken` for the Snowflake account.
    """

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRF-Token": csrf_token,
        "X-Snowflake-Context": f"{name.upper()}::https://{account_name}.{region}.snowflakecomputing.com",
        "Cookie": cookies,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    }

    # Create a connection - replace with proxy details if needed
    url = f"{app_server_url}/v0/organizations/{org_id}/entities/list"

    req = urllib.request.Request(
        url,
        headers=headers,
        method="POST",
        data="options=%7B%22sort%22%3A%7B%22col%22%3A%22modified%22%2C%22dir%22%3A%22desc%22%7D%2C%22limit%22%3A500%2C%22owner%22%3Anull%2C%22types%22%3A%5B%22query%22%5D%2C%22showNeverViewed%22%3A%22if-invited%22%7D&location=worksheets".encode(
            "utf-8"
        ),
    )

    # Perform the request and extract all queries.
    try:
        with urllib.request.urlopen(req) as response:
            response_data = json.loads(response.read().decode())
            queries = []

            for q in response_data["models"].get("queries", {}).values():
                queries.append(q)

            return queries

    except urllib.error.URLError as e:
        logging.info(e.reason)


def extract_worksheets(
    login_method: str,
    account_identifier: str,
    login_name: str,
    password=None,
    duo_passcode=None,
):
    # Validate that the URL is correct.
    logging.info("Validating URL for %s", account_identifier)
    validated = validate_snowflake_url(account_identifier)

    valid = validated["valid"]
    if valid is not True:
        print(f"Account identifier {account_identifier} is not valid")
        sys.exit(1)
    account_name = validated["account"]
    region = validated["region"]
    instance_url = validated["instance_url"]
    app_server_url = validated["app_server_url"]
    logging.info(
        "Validated account - account: %s, region: %s, instance_url: %s, app_server_url: %s",
        account_name,
        region,
        instance_url,
        app_server_url,
    )

    logging.info("Logging in using %s", login_method)

    # Step 1 - Build the login request payload, this varies depending on username/password, SSO, Duo
    data = {}
    if login_method == "password":
        data = login_username_password_payload(account_name, login_name, password)
    elif login_method == "sso":
        data = login_sso_payload(instance_url, account_name, login_name)
    elif login_method == "duo_passcode":
        data = login_duo_passcode_payload(
            instance_url, account_name, login_name, password, duo_passcode
        )

    # Step 2 - Perform the login request, see https://github.com/joshuataylor/snowflake-notes/blob/main/snowsight.md#login-request
    logging.debug("login payload - %s", data)
    logging.info("Logging into Snowflake..")
    login_data = login_request(instance_url, data)
    logging.info("Logged into Snowflake!")
    redirect_uri = login_data["redirect_uri"]
    name = login_data["name"]

    # Step 3 - Complete OAuth, returning cookies https://github.com/joshuataylor/snowflake-notes/blob/main/snowsight.md#complete-oauth-request
    logging.info("Completing OAuth Request")
    returned_cookies = complete_oauth(redirect_uri, account_name, region)
    logging.info("Completed OAuth.")
    logging.debug("Completed OAuth - Cookies - %s", returned_cookies)

    # Step 4 - Bootstrap as an authenticated user, to get the org_id + csrf_token.
    logging.info("Bootstrapping")
    bootstrap_data = snowsight_bootstrap(
        app_server_url, account_name, region, name, returned_cookies
    )
    logging.debug("Bootstrap returned - %s", bootstrap_data)

    org_id = bootstrap_data["org_id"]
    csrf_token = bootstrap_data["csrf_token"]

    logging.info("Bootstrapped - org_id - %s", org_id)

    # Step 5 - Fetch worksheets!
    logging.info("Fetching worksheets")

    worksheets = snowsight_entities(
        app_server_url, account_name, region, name, org_id, csrf_token, returned_cookies
    )

    logging.info("Found %s worksheets", len(worksheets))

    # loop over the returned worksheets
    for worksheet in worksheets:
        logging.info("%s - Name: %s", worksheet["slug"], worksheet["name"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process arguments.")

    # Required arguments
    parser.add_argument(
        "-m",
        "--method",
        help="Method to use",
        required=True,
        choices=["password", "sso", "duo", "duo_passcode"],
    )
    parser.add_argument(
        "-a", "--account-identifier", help="Account name", required=True
    )
    parser.add_argument("-u", "--login-name", help="Login name", required=True)

    # Password isn't always required, e.g., sso login/duo.
    parser.add_argument(
        "-p", "--password", help="Password", default=None, required=False
    )

    parser.add_argument(
        "-pc", "--passcode", help="Duo Passcode", default=None, required=False
    )

    # Default to INFO
    parser.add_argument(
        "-l",
        "--logging_level",
        help="Logging level",
        choices=["DEBUG", "INFO"],
        default="DEBUG",
        required=False,
    )

    # Parse the arguments
    args = parser.parse_args()
    logging_level = getattr(logging, args.logging_level)
    logging.basicConfig(level=logging_level)

    logging.info("Login Method - %s", args.method)
    logging.info("Account Identifier - %s", args.account_identifier)
    logging.info("Login name - %s", args.login_name)

    if args.password:
        logging.info("Password - <HIDDEN>")
    else:
        logging.info("Password - Not supplied")

    if args.logging_level == "DEBUG":
        logging.warning(
            "Showing full debug information, for less verbose information use -l INFO"
        )

    # ensure that if method = password, that the password was supplied.
    if args.method == "password" and args.password is None:
        logging.error("Please provide a password")
        sys.exit(1)

    extract_worksheets(
        args.method,
        args.account_identifier,
        args.login_name,
        args.password,
        args.passcode,
    )
