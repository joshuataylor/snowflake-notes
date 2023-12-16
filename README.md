# Snowflake Notes

This repository aims to document internal API endpoints that Snowflake connectors use, as well as documenting how to use the endpoints that Snowsight has. This does not cover the [Snowflake SQL REST API](https://docs.snowflake.com/en/developer-guide/sql-api/index).

These notes aim to be your companion when creating a driver/connector for an unsupported language, or when wanting to work with [Snowsight](https://docs.snowflake.com/en/user-guide/ui-snowsight)'s API.

I hope more awesome tools are created as a result!

## Who I Am

:wave:, I'm Josh Taylor, I am a [Senior Data Engineer at Sendle](https://www.linkedin.com/in/josh-taylor/), having worked with the Data Team using Snowflake since 2020. I have worked as a programmer since 2008.

I have looked into various aspects Snowflake such as creating drivers for Elixir/Rust, and I love to explore Snowflake (API Endpoints, how it returns data, etc) and other tools.

I hope you find these notes useful, and they help with any research you are doing as you explore Snowflakes nuances.

If you have any questions, feel free to email me (link on my GitHub profile) or start a discussion.

If you wish to contribute, submit feedback, etc - please create an issue or a Pull Request.

> [!IMPORTANT]
> Endpoints connectors use are pretty stable, but might change at anytime.

> [!IMPORTANT]
> If using an internal API (ie something from the Classic Console/Snowsight), Snowflake might also not be too happy if you start doing bulk requests to certain endpoints. These responses might also change at anytime. So play nicely.

> [!TIP]
> If you are just wanting to do basic queries etc with Snowflake, try using the official drivers as you'll have official support from Snowflake.

# Notes

- [Reverse Engineering Tips & Tricks](./reverse_engineering.md)

Outlines how to inspect requests to the Snowflake API, and how to setup a Reverse Proxy to inspect traffic to Snowsight.

- [Snowflake Connectors Flow](./snowflake_connectors_flow.md)

Provides documentation for how connectors authenticate to Snowflake, and perform queries, monitor queries, etc. Has cURL examples and example requests/responses.

# Other Resources

[sfsnowsightextensions](https://github.com/Snowflake-Labs/sfsnowsightextensions) is a Powershell tool to Create/List/Get Worksheets, however there is [an issue where this doesn't seem to work anymore](https://github.com/Snowflake-Labs/sfsnowsightextensions/issues/45)

> We are aware of changes to the Snowsight UI that will eventually cause breaking changes to snowsightextensions. In short, snowsightextensions is reaching end of life

# License
This repository is licensed under the Apache 2.0 license.

This repository references the following projects:

- [snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python) (Apache License Version 2.0)
- [snowflake-connector-nodejs](https://github.com/snowflakedb/snowflake-connector-nodejs) (Apache License Version 2.0)
- [pdo_snowflake](https://github.com/snowflakedb/pdo_snowflake) (Apache License Version 2.0)
- [snowflake-connector-net](https://github.com/snowflakedb/snowflake-connector-net) (Apache License Version 2.0)
- [snowflake-connector-jdbc](https://github.com/snowflakedb/snowflake-jdbc) (Apache License Version 2.0)

## Intellectual Property

This repository is NOT affiliated with Snowflake in anyway.

These notes and *very opinionated thoughts* are my own, and have been created in my personal time.

The views expressed are my own and do not reflect the opinions of current/past employers or Snowflake.

https://www.snowflake.com/wp-content/uploads/2019/01/Snowflake-Code-of-Business-Conduct-and-Ethics.pdf
https://www.snowflake.com/wp-content/uploads/2021/07/Partner-Content-Guidelines.pdf
https://www.snowflake.com/legal/snowflake-community-terms-of-service/
https://www.snowflake.com/legal/terms-of-service/