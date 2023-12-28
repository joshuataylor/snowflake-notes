# Private Key Auth for Snowsight

I have tried to get Private Keys working as an authentication method for Snowsight, as this would be great (as MFA is a pretty common requirement), but sending this payload:

```json
{"data": {"ACCOUNT_NAME": "<ACCOUNT_NAME>", "LOGIN_NAME": "<LOGIN_NAME>", "CLIENT_APP_ID": "Snowflake UI", "CLIENT_APP_VERSION": 20231219004219, "AUTHENTICATOR": "SNOWFLAKE_JWT", "TOKEN": "xxx"}}
```

Always returns a `token`/`masterToken`, which is used for drivers/"classic console".

No matter what I try I can't get this to a `redirectURI` or any other way that I could use to authenticate within Snowsight.

I've tried `disableDirectLogin=false` and other tricks such as setting the client environment, but nothing seems to work.

> [!IMPORTANT]
> If you know a a way to authenticate using a `token`/`masterToken` to the endpoints at `https://apps-api.c1.<REGION>.aws.app.snowflake.com`, such as `/bootstrap`, please reach out.

> We *could* use a `csrfToken` from an unauthenticated `/bootstrap` request for future requests.