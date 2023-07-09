<p align="center">
  <!-- <a href="https://gatewayd.io/docs/plugins/gatewayd-plugin-sql-idp"> -->
    <picture>
      <img alt="gatewayd-plugin-sql-idp-logo" src="https://github.com/gatewayd-io/gatewayd-plugin-sql-idp/blob/main/assets/gatewayd-plugin-sql-idp-logo.png" width="96" />
    </picture>
  <!-- </a> -->
  <h3 align="center">gatewayd-plugin-sql-idp</h3>
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

Running the above command causes the `go mod tidy` and `go build` to run for compiling and generating the plugin binary in the current directory, named `gatewayd-plugin-sql-idp`.

<!--
## Sentry

This plugin uses [Sentry](https://sentry.io) for error tracking. Sentry can be configured using the `SENTRY_DSN` environment variable. If `SENTRY_DSN` is not set, Sentry will not be used. -->
