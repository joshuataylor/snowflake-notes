# Reverse Engineering Tips & Tricks

When developing a new connector/driver or working on a tool that needs to use an internal/undocumented Snowflake API endpoint,
it can be handy to inspect traffic to Snowflake that see the requests these drivers make, and inspect requests you perform to see how Snowflake responds.

Connectors use HTTP(s) requests to communicate with Snowflake, so with a reverse proxy you can inspect all traffic.

So, what can we expect next?

> [!TIP]
> Basic working knowledge of APIs, JSON, etc will help when working with these endpoints.

## Official Drivers

As the Official Drivers are open-source, it's worth reading through these in a language you're familiar with before attempting to write a driver in a new language, to see any nuances/challenges you'll come across.

These connectors also usually note if anything major changes in terms of API compatibility (which from what I have seen since 2020 until December 2023, there has hasn't been any major breaking changes).

Also see [snowflake_drivers_workflow.md](snowflake_drivers_workflow.md) for a breakdown of the authentication and request process of Snowflake Drivers.

[Official Snowflake Drivers](https://docs.snowflake.com/en/developer-guide/drivers)

- [snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python) (Uses Arrow resultsets)
- [snowflake-connector-nodejs](https://github.com/snowflakedb/snowflake-connector-nodejs) (Uses JSON resultsets)

> I haven't looked too much into the other drivers, as Snowflake only returns JSON/Arrow which is handled from above.

- [pdo_snowflake](https://github.com/snowflakedb/pdo_snowflake)
- [snowflake-connector-net](https://github.com/snowflakedb/snowflake-connector-net)
- [snowflake-connector-jdbc](https://github.com/snowflakedb/snowflake-jdbc)

## Inspecting HTTP Requests

As Snowflake uses standard HTTP requests, using a Reverse Proxy is a great way to inspect requests to see how the connectors interact with Snowflake and see the Headers, POST baaaaaaaody etc.

I *highly recommend* [mitmproxy](https://mitmproxy.org/), it comes with [mitmweb](https://docs.mitmproxy.org/stable/#mitmweb) that allows you to easily inspect via a web-based user interface.

I also recommend [Proxyman](https://proxyman.io/) if using MacOS - it's not opensource, but the free version is great and the pro version even better.

### Inspecting your HTTP Requests

When you are making requests to Snowflake, with `mitmweb` you can inspect your requests using:

```sh
mitmweb --mode reverse:https://xxx.us-east-1.snowflakecomputing.com --listen-port 8083
```

Then use `http://localhost:8083` as your URL.