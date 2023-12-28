# MFA (Duo Auth) Authentication for Snowsight

> [!IMPORTANT]
> Create a test account for Duo when testing, so you don't lock out your main account!

[Snowflake MFA Docs](https://docs.snowflake.com/en/user-guide/security-mfa)

Seems this can be either via Push to Mobile, Phone Call or Text Message.

> You choose which when setting up.

I've tested with Push Notification, I believe the other authentication methods should be similar.

# MFA Passcode

The [Using MFA with SnowSQL](https://docs.snowflake.com/en/user-guide/security-mfa#using-mfa-with-snowsql) SF Docs show you can send the code that the Duo apps shows you in the request.

This would the preferred method, as you can type the code from their app, and you don't need to go through the hassle of authenticating, downside is you need their app.

Payload looks like this to `login-request`:

```json
{"data": {"ACCOUNT_NAME": "<ACCOUNT_NAME>", "LOGIN_NAME": "<LOGIN_NAME>", "CLIENT_APP_ID": "Snowflake UI", "CLIENT_APP_VERSION": 20231219004219, "PASSWORD": "<PASSWORD>", "EXT_AUTHN_DUO_METHOD": "passcode", "PASSCODE": "<PASSCODE>"}}
```

Valid Response:

```json
{
  "data" : {
  "nextAction" : "EXT_AUTHN_DUO_BEYOND",
  "inFlightCtx" : "ver:1-hint:foobar",
  "authnMethod" : "PASSWORD_MFA",
  "additionalAuthnData" : {
    "DUO_BEYOND_SIGN_REQUEST" : "TX|AAA=|BBB:APP|CCC=|DDD",
    "DUO_BEYOND_API_HOST" : "api-xxx.duosecurity.com",
    "DUO_SIGN_REQUEST" : "TX|AAA=|BBB:APP|CCC=|DDD",
    "DUO_API_HOST" : "api-xxx.duosecurity.com"
  }
},
  "code" : "390128",
  "message" : "Duo Security authentication is successful.",
  "success" : false,
  "headers" : null
}
```

Then you pass in the `inFlightCtx` to `login-request`, **note this is not inside the `data` object!**:

```json
{
    "data":
    {
        "CLIENT_APP_ID": "Snowflake UI",
        "CLIENT_APP_VERSION": 20231221140452
    },
    "inFlightCtx": "ver:1-hint:xxx"
}
```

This returns you the response as usual, with `redirectURI` having the `complete-url`.

# MFA Workflow

Using just the username/password, the login workflow looks like this:

## Step 1: Authentication as normal (Username/Password)

When authenticating with Duo, the response is:

```json
{
  "data": {
    "nextAction": "EXT_AUTHN_DUO_BEYOND",
    "inFlightCtx": "ver:1-hint:foobar",
    "authnMethod": "USERNAME_PASSWORD",
    "additionalAuthnData": {
      "DUO_BEYOND_SIGN_REQUEST": "TX|BBB=|CCC:APP|AAA=|DDD",
      "DUO_BEYOND_API_HOST": "api-71cb7a1c.duosecurity.com",
      "DUO_SIGN_REQUEST": "TX|BBB=|CCC:APP|AAA=|DDD",
      "DUO_API_HOST": "api-xxx.duosecurity.com"
    }
  },
  "code": "390124",
  "message": "Duo Security authentication is required.",
  "success": false,
  "headers": null
}
```

[Snowflake MFA Docs](https://docs.snowflake.com/en/user-guide/security-mfa)
Code `390124` - EXT_AUTHN_REQUESTED - Duo Security authentication is required.

## Step 2: Duo Web Auth

Duo then requires you to verify your token. It would be really handy to be able to query Duos API to ask it to send a specific method, instead of asking the user, which can be [done via their API](https://duo.com/docs/authapi#/auth)...

But alas, the way Snowflake does it is they redirect to:

`https://api-xxx.duosecurity.com/frame/web/v1/auth?tx=TX|BBB=|CCC&parent=https%3A%2F%2F<ACCOUNT_NAME>.<REGION>.snowflakecomputing.com%2Fconsole%2Flogin%23%2F&v=2.8` 

`BBB=|CCC` - The same `BBB=|CCC` as above, the string after `TX|` and before `:APP|`.

## Step 3: Duo Auth Callback

Once the user has confirmed their identity through Duo, they are pushed back to Duo.