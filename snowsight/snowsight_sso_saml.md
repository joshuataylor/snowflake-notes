# SSO SAML 2.0 Federated Authentication for Snowsight

> [!IMPORTANT]
> This is a work in progress document.

Many companies use SAML2 (also known as Federated Login) for authentication, allowing users to sign into various services using a centralised identity provider (IdP) such as Google, Azure, etc - SAML2 are usually locked behind enterprise pricing.

You can use whatever authentication provider you like - see the [Overview of federated authentication and SSO](https://docs.snowflake.com/en/user-guide/admin-security-fed-auth-overview#supported-identity-providers) documentation. Onelogin has a great [WTF is SAML page](https://www.onelogin.com/learn/saml).

> [!TIP]
> If testing authentication on a personal/trial account, there are some great __FREE__ hosted options out there now, such as [Auth0](https://auth0.com/pricing) (7500 active users on their free plan, more than enough for testing, not affiliated, no referral yada yada), there are also many great self-hosted options as well.

> [!IMPORTANT]
> Create a test account when testing, so you don't lock out your main account! __YOU ONLY GET A SINGLE EXTERNAL AUTH PROVIDER__

## SSO Setup Instructions

- [How To: Setup SSO with Auth0 and Snowflake New URL Format or Privatelink](https://community.snowflake.com/s/article/How-To-Setup-SSO-with-Auth0-and-Snowflake-New-URL-Format-or-Privatelink)
- [How To: Configure SSO authentication with Azure AD to Snowflake](https://community.snowflake.com/s/article/HOW-TO-Setup-SSO-with-Azure-AD-and-the-Snowflake-New-URL-Format-or-Privatelink)
- [How To: Configure Google Workspace as an Identity Provider for SSO with Snowflake](https://community.snowflake.com/s/article/configuring-g-suite-as-an-identity-provider)

## SSO Tips
- [Federated authentication and SSO troubleshooting](https://docs.snowflake.com/en/user-guide/errors-saml) has error codes and what they mean.
- Auth0 (and probably others) offers a log view of requests, to debug SSO issues.

## Snowsight UI SSO Authentication Workflow Summary

1. User visits `https://{ACCOUNTNAME}.{REGION}.snowflakecomputing.com`
2. They click `Sign in using <AUTHPROVIDER>` (the name is whatever you set)
![Login with SSO](assets/login_with_sso.png "Login with SSO")
3. They are redirected off to Authenticate through the IdP.
![Alt text](auth0_sso_example.png)
4. Once they have authenticated through the IdP, they are redirected back to `/fed/login`.
5. Authentication complete, they are logged in.

## SSO Authentication Breakdown

> [!IMPORTANT]
> These instructions assume that you have correctly configured SSO/SAML 2.0, and everything is working as expected, and you can login as per above.

> [!IMPORTANT]
> Snowflake requires a local webserver, as the user needs to be redirected back to this for the token to be sent. The way the Snowflake drivers do it is they [create a local webserver](https://github.com/snowflakedb/snowflake-connector-python/blob/main/src/snowflake/connector/auth/webbrowser.py#L117), listen on localhost, then close the server when authentication is complete.

> [!TIP]
> I have created an example implementation for Python 3.x at [snowsight_sso.py](../examples/snowsight/snowsight_sso.py), which requires no external dependencies and should be helpful to showcase how the SSO works. It will create a local webserver, which will then have verbose logging turned on.

### Login Request

#### Endpoint
`/session/v1/login-request?__uiAppName=Login`

#### Method
 `POST`

#### Headers
- Content-Type: `application/json`

#### Request Body

```json
{
  "data": {
    "CLIENT_APP_ID": "SnowflakeSQLAlchemy",
    "CLIENT_APP_VERSION": "1.5.1",
    "SVN_REVISION": null,
    "ACCOUNT_NAME": "<ACCOUNT_NAME>",
    "LOGIN_NAME": "<EMAIL_ADDRESS>",
    "AUTHENTICATOR": "EXTERNALBROWSER",
    "BROWSER_MODE_REDIRECT_PORT": "56981"
  }
}
```

> Snowflake UI is this.

```json
{
	"data": {
		"ACCOUNT_NAME": "<ACCOUNT_NAME>",
		"REAUTHENTICATION_TYPE": "FEDERATED",
		"CLIENT_APP_ID": "Snowflake UI",
		"CLIENT_APP_VERSION": 20231228094509
	}
}
```

##### Request Notes

1. `ACCOUNT_NAME` is your actual account name, without the region, as you're authenticating against the endpoint already.
2. `REAUTHENTICATION_TYPE` is `FEDERATED`, which impies it's SSO.
3. `CLIENT_APP_ID` - When set to `Snowflake UI`, a `redirectURI` is returned in the JSON. You'll need this when authenticating to Snowsight. Otherwise, if you pass any other value, the endpoint returns a `masterToken`/`token`.
4. `CLIENT_APP_VERSION` doesn't really matter, it seems it's just meta information as of 2023-12.

### Response

```json
{
  "data": {
    "nextAction": "FED_SP_AUTH",
    "redirectUrl": "https://example.com",
    "authnMethod": "FEDERATED"
  },
  "code": "390137",
  "message": "Federated authentication request URL is generated.",
  "success": false,
  "headers": null
}
```

1. `code` is the return code, `390137` means `FED_REAUTH` - `Federated authentication request URL is generated.` (see [Federated authentication and SSO troubleshooting](https://docs.snowflake.com/en/user-guide/errors-saml).
2. `redirectURI` is where you will be redirected to.
