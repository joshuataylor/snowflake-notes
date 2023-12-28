# Snowsight

This document aims to provide information about how to work with Snowsight, where the primary use case is working with Worksheets (previously called [Numeracy](https://www.snowflake.com/blog/numeracy-investing-in-our-query-ui/)).

For everything else that Snowsight offers such as database information, activity, query history, task history etc - you can use SQL to query these directly instead of relying on internal APIs.

## Snowsight UI

You can perform the following actions for Worksheets:

- Create/Run/Get/Delete [Worksheets](https://docs.snowflake.com/en/user-guide/ui-snowsight-worksheets)
- Create/Run/Get/Delete [Dashboards](https://docs.snowflake.com/en/user-guide/ui-snowsight-dashboards)
- Create/Delete [Folders](https://docs.snowflake.com/en/user-guide/ui-snowsight-worksheets#organizing-worksheets-in-folders)
- Create/Get/Delete [Filters](https://docs.snowflake.com/en/user-guide/ui-snowsight-query#using-filters-in-worksheets)
- [Get Query Profiler result for Worksheets](https://docs.snowflake.com/en/user-guide/ui-snowsight-query#view-the-query-profile)

## Example Implementation

There is an example implementation for Python 3.x at [snowsight_basic.py](examples%2Fsnowsight%2Fpython%2Fsnowsight_basic.py).

This aims to provide an example of how to Authenticate and return Worksheets.

> Usage: `python3 snowsight_basic.py <ACCOUNT_NAME> <REGION> <USERNAME> <PASSWORD>`

## Authentication Workflow Summary

Snowsight requires authentication in two ways:

1. Login via Username/Password (steps below)
2. [Login via Username/Password, with Duo for MFA](./snowsight_duo_mfa.md)
3. [Login via SSO SAML 2.0, using an IdP](./snowsight_sso_saml.md)

> It would be __FANTASTIC__ to use [Private Key Authentication](./snowsight_private_key_auth.md), if anyone knows how.. *please reach out.*

This is done using cookies, as these endpoints are aimed for users using browsers instead of consuming a "normal" API.

> The `/v1/` endpoints return token via `/session/v1/login-request` when authenticating, Snowsight requires cookies. See [snowflake_drivers_workflow](../snowflake_drivers_workflow.md) for more information about `v1`.

The authentication workflow looks like this:

1. `POST` to `session/v1/login-request`, which returns a `redirectURI`
2. `GET` the `redirectURL`, which returns a `set-cookie` in the header used to authenticate future requests.

## Login Request

### Endpoint
`/session/v1/login-request?__uiAppName=Login`

### Method
 `POST`

### Headers
- Content-Type: `application/json`

### Request Body

```json
{
    "data":
    {
        "ACCOUNT_NAME": "{ACCOUNT_NAME}",
        "LOGIN_NAME": "{USERNAME}",
        "PASSWORD": "{PASSWORD}",
        "CLIENT_APP_ID": "Snowflake UI",
        "CLIENT_APP_VERSION": 1234
    }
}
```

#### Request Notes

1. `ACCOUNT_NAME` is your actual account name, without the region, as you're authenticating against the endpoint already.
2. `LOGIN_NAME` is your username.
3. `PASSWORD` is your password.
4. `{REGION}` - Your Snowflake region.
5. `CLIENT_APP_ID` - When set to `Snowflake UI`, a `redirectURI` is returned in the JSON. You'll need this when authenticating to Snowsight. Otherwise, if you pass any other value, the endpoint returns a `masterToken`/`token`.

### Response

<details>
<summary>Example Valid Response</summary>

```json
{
  "data" : {
  "authnSubject" : {
    "loginUser" : {
      "loginName" : "YYY",
      "firstName" : "YOURNAME",
      "lastName" : "LASTNAME",
      "email" : "email@example.com",
      "createdOn" : 1600000000000,
      "defaultRole" : "SOMEROLE",
      "defaultNameSpace" : null,
      "defaultWarehouse" : "WAREHOUSE_NAME",
      "validationState" : "VALIDATED",
      "lastSucLogin" : 1600000000001
    }
  },
  "state" : "AUTHN_SUCCESS",
  "response" : null,
  "authnMethod" : "USERNAME_PASSWORD",
  "authnResInfo" : {
    "oauthAuthzServerIntegrationId" : 0,
    "accessTokenSnowflakeRoles" : null,
    "accessTokenRoles" : null,
    "oauthAccessTokenBeWithoutScopes" : false,
    "clientRequestAnyRoles" : false,
    "clientRequestDefaultRole" : false,
    "secureTokens" : false,
    "expirationTime" : -9223372036854775808,
    "userFriendlyConnectionName" : null,
    "connectionOrg" : null,
    "uiLandingPage" : "SNOWFLAKE_APP",
    "accessTokenIssuedByOAuthAuthzServer" : false,
    "accountActivation" : false
  },
  "integrationId" : -1,
  "authnEvent" : {
    "errorCodeStr" : null,
    "errorCode" : null,
    "externalId" : null,
    "clientVersion" : "1",
    "clientIP" : "123.123.123.123",
    "typeStr" : "LOGIN",
    "clientTypeStr" : "SNOWFLAKE_UI",
    "authnFactor1Str" : "PASSWORD",
    "authnFactor2Str" : null,
    "timestamp" : 1600000000002,
    "authnEventId" : 123,
    "userName" : "YYY"
  },
  "authnId" : null,
  "redirectURI" : "https://apps-api.c1.{REGION}.aws.app.snowflake.com/complete-oauth/snowflake?code={SOMECODE}",
  "accountName" : "{ACCOUNTNAME}"
},
  "code" : null,
  "message" : null,
  "success" : true
}
```

</details>

1. `createdOn` etc is a UNIX timestamp, millisecond precision.
2. `redirectURI` is used in the next step.

> [!IMPORTANT]
> The hostname from `redirectURI` is used in future requests as the primary endpoint, used for querying Bootstrap, Worksheets etc.
> -If it is `https://apps-api.c1.{REGION}.aws.app.snowflake.com/complete-oauth/snowflake?code={CODE}`, the hostname is `apps-api.c1.{REGION}.aws.app.snowflake.com`.

## Complete OAuth Request
### Endpoint
`/complete-oauth/snowflake?code={CODE}`

### Method
 `GET`

`{CODE}` - Using the returned code from above, but just use `redirectURL` returned from the `login-request` - it's easier as this might.

The `state` part is needed, it's the URL of your instance.

Example cURL Command:

```sh
curl 'https://apps-api.c1.{REGION}.aws.app.snowflake.com/complete-oauth/snowflake?code={CODE}&state=%7B%22url%22%3A%22https%3A%2F%2F{ACCOUNTNAME}.{REGION}.snowflakecomputing.com%22%7'
```

### Complete OAuth Response

The response is HTML, but we only care about the cookie headers:

```
set-cookie: S8_SESSION_{USERNAME}__https___{ACCOUNTNAME}_{REGION}_snowflakecomputing_com=yyyy; path=/; secure; HttpOnly
set-cookie: user-xxx="yyy="; Version=1; Path=/; Secure; HttpOnly; Max-Age=86400; Expires=Tue, 19-Dec-2000 00:00:00 GMT
```

Store all the cookies you receive for future requests.

## Bootstrap

Snowflake requires an `OrganizationID` and `csrfToken` for Snowsight endpoints, which you can retrieve from the `bootstrap` endpoint.

> [!TIP]
> This endpoint also returns other useful information about the logged in user if you need that for other purposes. (though you can get this information from views in the Snowflake database).

### Bootstrap Request

`/boostrap`

#### Method

 `GET`

#### Headers

- `X-Snowflake-Context: {USERNAME}::https://{ACCOUNTNAME}.{REGION}.snowflakecomputing.com`

> [!TIP]
> This header + cookies are required on all future requests.

Example cURL Request:

```sh
curl 'https://apps-api.c1.{REGION}.aws.app.snowflake.com/bootstrap' \
-H 'X-Snowflake-Context: {USERNAME}::https://{ACCOUNTNAME}.{REGION}.snowflakecomputing.com' \
--cookie '{COOKIES}'
```

### Bootstrap Response

The response is quite large, here is a sample of the organisation information:

```json
{
    "User":
    {
        "defaultOrgId": "12345",
        "orgId": "12345",
        "organizations":
        [
            {
                "id": "12345"
            }
        ]
    },
    "Org":
    {
        "id": "12345"
    },
    "PageParams":
    {
        "csrfToken": "5cb94c74",
    }
}
```

`OrganizationID` is from either:

1. `Org` -> `id`.
2. That value can be null/empty, fall back to `User` -> `defaultOrgId`/`orgId`.

### Snowsight Request Requirements

Now you have the following:

1. Cookies
2. `csrfToken`
3. `organizationID`

You can actually perform requests against Snowsight.

Every Snowsight request requires the following headers:

1. `X-Snowflake-Context: {USERNAME}::https://{ACCOUNTNAME}.{REGION}.snowflakecomputing.com`
2. `X-CSRF-Token: {CSRFTOKEN}`

As well as the cookies.

## Worksheets

### Get all Worksheets
#### Summary
Returns all worksheets/folders/folders. Snowflake seems to call these `entities`, as it can contain multiple types.

##### Endpoint
`/v0/organizations/{ORGANIZATIONID}/entities/list`

##### Method
 `POST`

##### Headers
- Content-Type: `application/x-www-form-urlencoded`
- Accept: `application/json`

- Returns: JSON

#### Get all Worksheets Request Notes

1. The limit for this endpoint seems to be `500`.
2. `types` are `query`, `dashboard`, `folder`.
3. `col` seems to be `modified` (when the item was last modified) and `viewed` (when the item was last viewed)

#### Get all Worksheets Request Body

This request requires a form body, see the [Mozilla Docs about HTTP Post](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST) for more information.

The unencoded request looks like this:

```json
options={"sort":{"col":"modified","dir":"desc"},"limit":500,"owner":null,"types":["query"],"showNeverViewed":"if-invited"}&location=worksheets
```

The `options` part in the request **must be URL encoded**:

```json
options=%7B%22sort%22%3A%7B%22col%22%3A%22modified%22%2C%22dir%22%3A%22desc%22%7D%2C%22limit%22%3A500%2C%22owner%22%3Anull%2C%22types%22%3A%5B%22query%22%5D%2C%22showNeverViewed%22%3A%22if-invited%22%7D&location=worksheets
```

Example cURL request:

```sh
curl 'https://apps-api.c1.{REGION}.aws.app.snowflake.com/v0/organizations/{ORGANIZATIONID}/entities/list' \
-X POST \
-H 'X-Snowflake-Context: {USERNAME}::https://{ACCOUNTNAME}.{REGION}.snowflakecomputing.com' \
-H 'X-CSRF-Token: {CSRFTOKEN}' \
-H 'Content-Type: application/x-www-form-urlencoded' \
--cookie '{COOKIE}' \
--data-raw 'options=%7B%22sort%22%3A%7B%22col%22%3A%22modified%22%2C%22dir%22%3A%22desc%22%7D%2C%22limit%22%3A500%2C%22owner%22%3Anull%2C%22types%22%3A%5B%22query%22%5D%2C%22showNeverViewed%22%3A%22if-invited%22%7D&location=worksheets'
```

<details>
<summary>Example entities/list Response</summary>

```json
{
    "entities":
    [
        {
            "entityId": "{entityId}",
            "entityType": "query",
            "info":
            {
                "name": "myexample",
                "slug": "{SLUG}",
                "version": 0,
                "content": "",
                "dashboardRows":
                [],
                "folderId": null,
                "folderName": null,
                "folderType": null,
                "visibility": "private",
                "ownerId": 111111111111,
                "modified": "2023-12-18T16:01:29.67626Z",
                "created": "2023-12-18T16:01:20.221961Z",
                "viewed": null,
                "queryLanguage": "sql",
                "role": "{ROLE}",
                "url": "/{prefix}/{accountname}/{SLUG}#query"
            },
            "match": null
        }
    ],
    "hasRecentEntities": true,
    "models":
    {
        "folders":
        {
            "{folderId}":
            {
                "id": "{folderId}",
                "orgId": "211111111111",
                "name": "Some Folder",
                "ownerId": "111111111111",
                "type": "list",
                "visibility": "private",
                "refreshing": false,
                "refreshed": "2023-01-01T00:00:00.000000Z",
                "modified": "2023-01-01T00:00:00.000000Z",
                "settings":
                {
                    "dashboard":
                    {
                        "rows": null,
                        "manualRefresh": false,
                        "context":
                        {
                            "role": "",
                            "warehouse": "",
                            "database": "",
                            "schema": "",
                            "secondaryRoles": ""
                        }
                    },
                    "unsavedParams": null
                },
                "paramRefs":
                [],
                "isImported": false,
                "isRefreshDead": false,
                "lastRefreshJobId": null,
                "hbVersion": null,
                "slug": "someslug",
                "editable": true,
                "runnable": true,
                "resultsViewable": true,
                "url": "/{prefix}/{accountname}/#/someslug",
                "members":
                [
                    {
                        "memberType": "user",
                        "userId": "111111111111",
                        "memberId": "111111111111",
                        "role": "owner",
                        "hasRole": true
                    }
                ],
                "executionContext":
                {
                    "role": "{ROLE}",
                    "warehouse": "",
                    "database": "",
                    "schema": "",
                    "secondaryRoles": "NONE"
                }
            }
        },
        "queries":
        {
            "{entityId}":
            {
                "snowflakeRequestId": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                "snowflakeQueryId": "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "runner": "111111111111",
                "query": "select 2 as bar",
                "queryContext":
                {
                    "role": "{ROLE}",
                    "warehouse": "{WAREHOUSE}",
                    "database": "",
                    "schema": "",
                    "secondaryRoles": "NONE"
                },
                "queryRange":
                {
                    "start": 0,
                    "end": 15,
                    "allowRewrites": false
                },
                "startDate": "2023-12-18T00:00:00.000000000Z",
                "endDate": "2023-12-18T00:00:00.000000000Z",
                "drafts":
                {
                    "111111111111":
                    {
                        "query": "select 2 as bar",
                        "paramRefs":
                        [],
                        "queryRange": null,
                        "executionContext":
                        {
                            "role": "{ROLE}",
                            "warehouse": "{WAREHOUSE}",
                            "database": "",
                            "schema": "",
                            "secondaryRoles": "NONE"
                        },
                        "queryLanguage": "sql",
                        "appSessionId": 2000000000000
                    }
                },
                "draftUpdates":
                {
                    "111111111111": 1702915289669
                },
                "transforms":
                [],
                "queryLanguage": "sql",
                "appSessionId": 2000000000000,
                "gsQueryMetadata":
                {
                    "startTime": 1700000000000,
                    "endTime": 1700000000000,
                    "sqlText": "select 2 as bar",
                    "state": "SUCCEEDED",
                    "statesDuration": "[16,0,1,0,0,0,0,0,0,0,0,0,11,0,0,0,0,0,0,0,0,0,0,0]",
                    "stats":
                    {
                        "compilationTime": 16,
                        "gsExecTime": 1
                    },
                    "status": "SUCCESS",
                    "totalDuration": 28,
                    "warehouseName": "{WAREHOUSE}"
                },
                "pid": "{entityId}",
                "name": "myexample",
                "orgId": "211111111111",
                "ownerId": "111111111111",
                "folderId": null,
                "visibility": "private",
                "layout":
                {
                    "explorer":
                    {
                        "topHeight": 0,
                        "mode": "CUSTOM"
                    },
                    "pinned":
                    {
                        "topHeight": 0,
                        "mode": "CUSTOM"
                    },
                    "results":
                    {
                        "topHeight": 0,
                        "mode": "OPEN_SPLIT"
                    },
                    "schema":
                    {
                        "topHeight": 0,
                        "mode": "OPEN_SPLIT"
                    },
                    "visualization":
                    {
                        "topHeight": 0,
                        "mode": "OPEN_SPLIT"
                    }
                },
                "modified": "2023-12-18T00:00:00.00000Z",
                "version": 2,
                "isParamQuery": false,
                "projectType": "query",
                "executionContext":
                {
                    "role": "{ROLE}",
                    "warehouse": "{WAREHOUSE}",
                    "database": "",
                    "schema": "",
                    "secondaryRoles": "NONE"
                },
                "editable": true,
                "runnable": true,
                "resultsViewable": true,
                "url": "/{prefix}/{accountname}/{SLUG}#query",
                "slug": "{SLUG}",
                "members":
                [
                    {
                        "memberType": "user",
                        "userId": "111111111111",
                        "memberId": "111111111111",
                        "role": "owner",
                        "hasRole": true
                    }
                ],
                "hasRequiredRole": true
            }
        },
        "dbSchemas":
        {},
        "worksheetImports":
        {},
        "drafts":
        {
            "{entityId}":
            {
                "query": "select 2 as bar",
                "paramRefs":
                [],
                "queryRange": null,
                "executionContext":
                {
                    "role": "MYROLE",
                    "warehouse": "MYWAREHOUSE",
                    "database": "",
                    "schema": "",
                    "secondaryRoles": "NONE"
                },
                "queryLanguage": "sql",
                "appSessionId": 1011111111111,
                "version": 2,
                "modifiedTime": 16000000000021
            }
        },
    },
    "next": ""
}
```
</details>

### Worksheets Response

Returns a JSON response containing an object of entities/models.

This seems to have Worksheets in the following objects:

1. `entities`
`entities` is a list of objects containing information about queries, has very bare information:

```json
{
    "entities":
    [
        {
            "entityId": "{entityId}",
            "entityType": "query",
            "info":
            {
                "name": "myexample",
                "slug": "{SLUG}",
                "version": 0,
                "content": "",
                "dashboardRows":
                [],
                "folderId": null,
                "folderName": null,
                "folderType": null,
                "visibility": "private",
                "ownerId": 111111111111,
                "modified": "2023-12-18T16:01:29.67626Z",
                "created": "2023-12-18T16:01:20.221961Z",
                "viewed": null,
                "queryLanguage": "sql",
                "role": "{ROLE}",
                "url": "/{prefix}/{accountname}/{SLUG}#query"
            },
            "match": null
        }
    ]
}
```

2. `models`

`models` is an object containing `folders` , `queries`, `dbSchemas`, `worksheetImports` (from classic console?) and `drafts`.

> For an example JSON response, see the above `Example entities/list Response`.

To get the full Worksheet information such as SQL, timings, etc, you'll need to iterate over `models.queries`,
noting that `queries` are objects and not a list.