# Snowflake Notes

This repository aims to document and share insights into how Snowflake works under the hood, helping de-mystify some of Snowflakes undocumented internals.

Initially there is a focus on documenting "internal" API Endpoints that drivers and [Snowsight](https://docs.snowflake.com/en/user-guide/ui-snowsight) uses, to help share undocumented information/nuances that isn't publicly accessible.

These notes aims to be your companion when working with these API endpoints, with the intention of unlocking use cases such as:

- Creating a driver for an unsupported language
- Accessing Snowsights APIs to get Worksheet/Dashboard information
- Using internal APIs for query information/query profiler information and unlock features not yet accessible via SQL.

I hope more awesome tools are created as a result of these, and a more collaborative discussion can be had.

## About the Author

:wave:, I'm Josh Taylor, I am a [Senior Data Engineer at Sendle](https://www.linkedin.com/in/josh-taylor/), having worked with the Data Team using Snowflake since 2020, transitioning from being a Software Engineer since 2008.

I have really enjoyed digging into Snowflakes internals, such as creating drivers for Elixir/Rust, understanding how things work "under the hood" has been quite fun.

I hope you find these notes useful, and they help with any research you are doing as you explore Snowflakes internals, and hope you share any notes, comments and other insights you have found when dealing with Snowflakes "nuances".

> [!NOTE]
> If you have any questions, feel free to email me (link on my GitHub profile) or start a discussion.
> - If you wish to contribute, submit feedback, etc - please create an issue or a Pull Request.

> [!IMPORTANT]
> Endpoints that drivers use are pretty stable, but might change at anytime.
> - If using an internal API (ie something from the Classic Console/Snowsight), Snowflake *might also not be too happy if you start doing bulk requests to certain endpoints*. These responses might also change at anytime. So play nicely.

> [!TIP]
> If you are just wanting to do basic queries etc with Snowflake, try using the official drivers as you'll have official support from Snowflake.

## Notes - Table of Contents

- [Reverse Engineering Tips & Tricks](reverse_engineering_tips.md)

Outlines how to inspect requests to the Snowflake API, and how to setup a Reverse Proxy to inspect traffic to Snowsight.

- [Snowflake Connectors Flow](snowflake_drivers_workflow.md)

Provides documentation for how connectors authenticate to Snowflake, and perform queries, monitor queries, etc. Has cURL examples and example requests/responses.

- [Snowsight](snowsight.md)

Covers how to authenticate to Snowsight, and perform queries to retrieve worksheets. Also see an example Python 3.x implementation - [snowsight_basic.py](examples%2Fsnowsight%2Fpython%2Fsnowsight_basic.py).

## Other Resources

There has been some great posts/resources from the community which cover the internals and other tips when using Snowflake.

If you have come across resources relating to Snowflake internals, please share!

> [!TIP]
> The [select.dev blog is fantastic](https://select.dev/posts), some of my favourites:

- [Introduction to Snowflake's Micro-Partitions](https://select.dev/posts/introduction-to-snowflake-micro-partitions)
- [How to speed up range joins in Snowflake by 300x](https://select.dev/posts/snowflake-range-join-optimization)
- [Essential Snowflake Optimization Strategies](https://select.dev/posts/essential-snowflake-optimization-strategies)
- [Should you use CTEs in Snowflake?](https://select.dev/posts/should-you-use-ctes-in-snowflake)
- [Effectively using the MERGE command in Snowflake](https://select.dev/posts/snowflake-merges)
- [A deep dive into Snowflake storage costs](https://select.dev/posts/snowflake-storage)

### Snowflake Tools

Snowflake has created some various tools which might be of interest:

- [sfsnowsightextensions](https://github.com/Snowflake-Labs/sfsnowsightextensions) is a Powershell tool to Create/List/Get Worksheets, however there is [an issue where this doesn't seem to work anymore](https://github.com/Snowflake-Labs/sfsnowsightextensions/issues/45)

> We are aware of changes to the Snowsight UI that will eventually cause breaking changes to snowsightextensions. In short, snowsightextensions is reaching end of life.

## License

This repository is licensed under the Apache 2.0 license.

This repository is NOT affiliated with Snowflake, nor endorsed by Snowflake in any way, shape, or form. This repository does not intend to infringe on any trademarks or copyrights that belong to Snowflake, it's intended to aid curiosity

These notes, opinions, thoughts and other ramblings are my own (unless contributed by others, thanks!), and have been created in my personal time, with the intention of helping others learn and create interesting tools - they do not reflect the opinions of current/past employers nor Snowflake.

Where possible I have tried to follow the [Terms of Service](https://www.snowflake.com/legal/terms-of-service/) and the [Community Terms of Service](https://www.snowflake.com/legal/snowflake-community-terms-of-service/). [Snowflake Code of Business Conduct and Ethics](https://www.snowflake.com/wp-content/uploads/2019/01/Snowflake-Code-of-Business-Conduct-and-Ethics.pdf) and [Partner Content Guidelines](https://www.snowflake.com/wp-content/uploads/2021/07/Partner-Content-Guidelines.pdf) have been referenced where relevant as well.

This repository references the following projects:

- [snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python) (Apache License Version 2.0)
- [snowflake-connector-nodejs](https://github.com/snowflakedb/snowflake-connector-nodejs) (Apache License Version 2.0)
- [pdo_snowflake](https://github.com/snowflakedb/pdo_snowflake) (Apache License Version 2.0)
- [snowflake-connector-net](https://github.com/snowflakedb/snowflake-connector-net) (Apache License Version 2.0)
- [snowflake-connector-jdbc](https://github.com/snowflakedb/snowflake-jdbc) (Apache License Version 2.0)