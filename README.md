<p align="center">
  <!-- <a href="https://gatewayd.io/docs/plugins/gatewayd-plugin-sql-ids-ips"> -->
    <picture>
      <img alt="gatewayd-plugin-sql-ids-ips-logo" src="https://github.com/gatewayd-io/gatewayd-plugin-sql-ids-ips/blob/main/assets/gatewayd-plugin-sql-ids-ips-logo.png" width="96" />
    </picture>
  <!-- </a> -->
  <h3 align="center">gatewayd-plugin-sql-ids-ips</h3>
  <p align="center">GatewayD plugin for SQL injection detection and prevention.</p>
</p>

## Features

- Detects SQL injection attacks using two methods:
  - **Signature-based detection**: Detects SQL injection attacks by matching incoming queries against a list of known malicious queries using a trained deep learning model with Tensorflow and Keras
  - **Syntax-based detection**: Detects SQL injection attacks by parsing incoming queries and checking for suspicious syntax using `libinjection`
- Prevents SQL injection attacks by blocking malicious queries from reaching the database server, and returning an error to the client instead
- Prometheus metrics for quantifying detections
- Logging
- Configurable via environment variables

## Build for testing

To build the plugin for development and testing, run the following command:

```bash
make build-dev
```

Running the above command causes the `go mod tidy` and `go build` to run for compiling and generating the plugin binary in the current directory, named `gatewayd-plugin-sql-ids-ips`.

<!--
## Sentry

This plugin uses [Sentry](https://sentry.io) for error tracking. Sentry can be configured using the `SENTRY_DSN` environment variable. If `SENTRY_DSN` is not set, Sentry will not be used. -->

## Contributing

We welcome contributions from everyone.<!-- Please read our [contributing guide](https://gatewayd-io.github.io/CONTIBUTING.md) for more details.--> Just open an [issue](https://github.com/gatewayd-io/gatewayd-plugin-sql-ids-ips/issues) or send us a [pull request](https://github.com/gatewayd-io/gatewayd-plugin-sql-ids-ips/pulls).

## License

This plugin is licensed under the [Affero General Public License v3.0](https://github.com/gatewayd-io/gatewayd-plugin-sql-ids-ips/blob/main/LICENSE).
