# Snowflake Connectors Workflow

This document aims to explain in detail how Snowflake drivers work, how they authenticate, perform queries, and other features you can use.

These notes should be helpful when developing a Snowflake driver or needing to query specific endpoints.

## Usecase

These are the endpoints that the [official drivers](https://docs.snowflake.com/en/developer-guide/drivers) use with Snowflake.

## Capabilities

Login, perform queries, query monitoring, abort queries, fetch query result sets, basically anything a driver can do.

## Endpoints

### Login

#### Summary

The login endpoint (`session/v1/login-request`) expects a POST request containing a JSON body with your Snowflake credentials.

On successful login, the endpoint returns a `token`, which you use when accessing other endpoints.

> [!TIP]
> Other endpoints are authenticated using the `Authorization` header, with `Snowflake Token="xxx"`.

#### cURL Examples

Here are some cURL examples you can use to login:

<details>
<summary>Login Request</summary>

```bash
curl 'https://xxx.us-east-1.snowflakecomputing.com/session/v1/login-request' \
-X POST \
-H 'Host: xxx.us-east-1.snowflakecomputing.com' \
-H 'Accept: application/json' \
-H 'Content-Type: application/json' \
--data-raw '{
  "data": {
    "ACCOUNT_NAME": "xxx.us-east-1",
    "PASSWORD": "xxx",
    "CLIENT_APP_ID": "JavaScript",
    "CLIENT_APP_VERSION": "1.5.3",
    "LOGIN_NAME": "yourusername",
    "SESSION_PARAMETERS": {
      "VALIDATE_DEFAULT_PARAMETERS": "true",
      "QUOTED_IDENTIFIERS_IGNORE_CASE": "true"
    },
    "CLIENT_ENVIRONMENT": {
      "schema": "yourschema",
      "tracing": "DEBUG",
      "OS": "Linux",
      "OCSP_MODE": "FAIL_OPEN",
      "APPLICATION": "MYAWESOMEAPP",
      "warehouse": "yourwarehouse",
      "database": "yourdatabase",
      "serverURL": "https://xxx.us-east-1.snowflakecomputing.com",
      "user": "yourusername",
      "account": "xxx.us-east-1"
    }
  }
}
'
```

</details>

#### Response Example

<details>
<summary>Example Response</summary>

Valid response:

```json
{
  "data": {
    "masterToken": "ver:3-hint:xxx",
    "token": "ver:3-hint:xxx",
    "validityInSeconds": 3600,
    "masterValidityInSeconds": 14400,
    "displayUserName": "My User",
    "serverVersion": "7.44.2",
    "firstLogin": false,
    "remMeToken": null,
    "remMeValidityInSeconds": 0,
    "healthCheckInterval": 45,
    "newClientForUpgrade": null,
    "sessionId": 111111111111111,
    "parameters": [
      {
        "name": "TIMESTAMP_OUTPUT_FORMAT",
        "value": "YYYY-MM-DD HH24:MI:SS.FF3 TZHTZM"
      },
      {
        "name": "CLIENT_PREFETCH_THREADS",
        "value": 4
      },
      {
        "name": "JS_TREAT_INTEGER_AS_BIGINT",
        "value": false
      },
      {
        "name": "TIME_OUTPUT_FORMAT",
        "value": "HH24:MI:SS"
      },
      {
        "name": "CLIENT_RESULT_CHUNK_SIZE",
        "value": 160
      },
      {
        "name": "TIMESTAMP_TZ_OUTPUT_FORMAT",
        "value": ""
      },
      {
        "name": "CLIENT_SESSION_KEEP_ALIVE",
        "value": false
      },
      {
        "name": "CLIENT_OUT_OF_BAND_TELEMETRY_ENABLED",
        "value": false
      },
      {
        "name": "CLIENT_METADATA_USE_SESSION_DATABASE",
        "value": false
      },
      {
        "name": "QUERY_CONTEXT_CACHE_SIZE",
        "value": 5
      },
      {
        "name": "ENABLE_STAGE_S3_PRIVATELINK_FOR_US_EAST_1",
        "value": false
      },
      {
        "name": "TIMESTAMP_NTZ_OUTPUT_FORMAT",
        "value": "YYYY-MM-DD HH24:MI:SS.FF3"
      },
      {
        "name": "CLIENT_RESULT_PREFETCH_THREADS",
        "value": 1
      },
      {
        "name": "CLIENT_METADATA_REQUEST_USE_CONNECTION_CTX",
        "value": false
      },
      {
        "name": "CLIENT_HONOR_CLIENT_TZ_FOR_TIMESTAMP_NTZ",
        "value": true
      },
      {
        "name": "CLIENT_MEMORY_LIMIT",
        "value": 1536
      },
      {
        "name": "CLIENT_TIMESTAMP_TYPE_MAPPING",
        "value": "TIMESTAMP_LTZ"
      },
      {
        "name": "TIMEZONE",
        "value": "UTC"
      },
      {
        "name": "CLIENT_RESULT_PREFETCH_SLOTS",
        "value": 2
      },
      {
        "name": "CLIENT_TELEMETRY_ENABLED",
        "value": true
      },
      {
        "name": "CLIENT_USE_V1_QUERY_API",
        "value": true
      },
      {
        "name": "CLIENT_DISABLE_INCIDENTS",
        "value": true
      },
      {
        "name": "CLIENT_RESULT_COLUMN_CASE_INSENSITIVE",
        "value": false
      },
      {
        "name": "BINARY_OUTPUT_FORMAT",
        "value": "HEX"
      },
      {
        "name": "CSV_TIMESTAMP_FORMAT",
        "value": ""
      },
      {
        "name": "CLIENT_ENABLE_LOG_INFO_STATEMENT_PARAMETERS",
        "value": false
      },
      {
        "name": "JS_DRIVER_DISABLE_OCSP_FOR_NON_SF_ENDPOINTS",
        "value": false
      },
      {
        "name": "CLIENT_TELEMETRY_SESSIONLESS_ENABLED",
        "value": true
      },
      {
        "name": "CLIENT_CONSENT_CACHE_ID_TOKEN",
        "value": false
      },
      {
        "name": "CLIENT_FORCE_PROTECT_ID_TOKEN",
        "value": true
      },
      {
        "name": "DATE_OUTPUT_FORMAT",
        "value": "YYYY-MM-DD"
      },
      {
        "name": "CLIENT_STAGE_ARRAY_BINDING_THRESHOLD",
        "value": 65280
      },
      {
        "name": "CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY",
        "value": 3600
      },
      {
        "name": "AUTOCOMMIT",
        "value": true
      },
      {
        "name": "CLIENT_SESSION_CLONE",
        "value": false
      },
      {
        "name": "TIMESTAMP_LTZ_OUTPUT_FORMAT",
        "value": ""
      }
    ],
    "sessionInfo": {
      "databaseName": null,
      "schemaName": null,
      "warehouseName": "XXX",
      "roleName": "YYY"
    },
    "idToken": null,
    "idTokenValidityInSeconds": 0,
    "responseData": null,
    "mfaToken": null,
    "mfaTokenValidityInSeconds": 0
  },
  "code": null,
  "message": null,
  "success": true
}
```

</details>

#### Request

##### Endpoint

`/session/v1/login-request`

##### Method

 `POST`

##### Headers

- Content-Type: `application/json`
- Accept: `application/json`

##### Request Body

```json
{
  "data": {
    "ACCOUNT_NAME": "account_name",
    "PASSWORD": "password",
    "CLIENT_APP_ID": "JavaScript",
    "CLIENT_APP_VERSION": "1.5.3",
    "LOGIN_NAME": "username",
    "SESSION_PARAMETERS": {
      "VALIDATE_DEFAULT_PARAMETERS": "true",
      "QUOTED_IDENTIFIERS_IGNORE_CASE": "true"
    },
    "CLIENT_ENVIRONMENT": {
      "schema": "schema",
      "tracing": "DEBUG",
      "OS": "Linux",
      "OCSP_MODE": "FAIL_OPEN",
      "APPLICATION": "MYAWESOMEAPP",
      "warehouse": "WAREHOUSE_NAME",
      "database": "DATABASE_NAME",
      "serverURL": "https://youraccount.snowflakecomputing.com",
      "user": "username",
      "account": "account_name"
    }
  }
}
```

```
barrr
```

###### ACCOUNT_NAME

Your account name + region, eg `foo12345.us-east-1`.

###### PASSWORD

Your password :-).

###### LOGIN_NAME

Your username.

###### CLIENT_APP_ID / CLIENT_APP_VERSION

This determines the type of data you are returned when querying for rows, as Snowflake returns either JSON or Arrow resultsets.

> [!NOTE]
> For additional information about Arrow Streams, see the [Apache Arrow documentation about streaming files from Arrow](https://arrow.apache.org/docs/python/ipc.html).

This is because certain languages don't have support for Arrow yet, and fallback to using JSON Resultsets (Node.js, etc).

This information is shown in the Classic Console when viewing a query, the version might show a warning that it is no longer supported by Snowflake if it's set too low.

> [!TIP]
> I highly recommend trying to use Arrow, if your language supports it, it's much faster to process on the client, and the download size is usually far smaller.

JSON Resultsets:

- CLIENT_APP_ID: `JavaScript`
- CLIENT_APP_VERSION: `1.5.3`

> this is used by the [Node.js driver](https://docs.snowflake.com/en/developer-guide/node-js/nodejs-driver)

Arrow Resultsets:

- CLIENT_APP_ID: `PythonConnector`
- CLIENT_APP_VERSION: `2.7.8`

> This is used by the [Python driver](https://github.com/snowflakedb/snowflake-connector-python)

###### SESSION_PARAMETERS

You can set [session parameters](https://docs.snowflake.com/en/sql-reference/parameters) when logging in.

I recommend using these:

1. `VALIDATE_DEFAULT_PARAMETERS: true`
Validates that the parameters are correct.

2. `QUOTED_IDENTIFIERS_IGNORE_CASE: true`
Ignores case for quoted identifiers, [see](https://docs.snowflake.com/en/sql-reference/identifiers-syntax#migrating-from-databases-that-treat-double-quoted-identifiers-as-case-insensitive) docs](<https://docs.snowflake.com/en/sql-reference/identifiers-syntax#migrating-from-databases-that-treat-double-quoted-identifiers-as-case-insensitive>). This helps work around issues if you're implementing for a language with database drivers that don't expect this behavior.

###### CLIENT_ENVIRONMENT

Sets various parameters such as warehouse, role, etc.

*required*:

- `serverURL`: `https://youraccount.snowflakecomputing.com`
- `user`: Your username.
- `account`: Your account name + region, eg `foo12345.us-east-1`.
- `database`: Name of the database.
- `schema`: Schema name to use.
- `warehouse`: Name of the warehouse to use.
- `OCSP_MODE: FAIL_OPEN` See [docs](https://docs.snowflake.com/en/user-guide/ocsp)

*optional*:

- `tracing`: Used to tell to the client you want additional tracing, I don't believe Snowflake themselves send more information/context. Values: `DEBUG`, etc.

- `OS`: Meta information, I usually use `Linux`.
- `APPLICATION` - Displays your application name in the query history, useful for debugging.

## Query Request

To perform queries against Snowflake, you'll need a Token from above.

`/queries/v1/query-request`

```sh
curl 'https://xx.us-east-1.snowflakecomputing.com/queries/v1/query-request' \
-X POST \
-H 'Host: xxx.us-east-1.snowflakecomputing.com' \
-H 'accept: application/snowflake' \
-H 'Authorization: Snowflake Token="ver:3-hint:xxxx"' \
-H 'Content-Type: application/json' \
--data-raw '{"sqlText": "select 2 as x", "asyncExec": false, "sequenceId": 0, "parameters": {}}'
```

"accept", "application/snowflake

## Get Query Results

`/queries/{QUERY_ID}/result` GET

## Abort Query

`/queries/v1/abort-request` POST

`/queries/13f12818-de4c-41d2-bf19-f115ee8a5cc1/abort-request` POST

`/session/authenticator-request`
