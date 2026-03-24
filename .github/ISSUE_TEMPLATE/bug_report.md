---
name: Bug report
about: Something is not working correctly
labels: bug
---

## Describe the bug

A clear and concise description of what is wrong.

## Command that triggered the bug

```sh
beacon scan --domain example.com --format json
# (replace with the exact command you ran)
```

## Expected behaviour

What you expected to happen.

## Actual behaviour

What actually happened. Include the full output from stderr and stdout if relevant.

```
# paste output here
```

## Beacon version

Run `beacon --help` and paste the first line, or report the git commit SHA if building from source.

## Go version

```sh
go version
```

## OS and architecture

<!-- e.g. macOS 14.3 arm64, Ubuntu 22.04 x86_64, Alpine 3.19 in Docker -->

## Installed external tools

Paste the output of `beacon install` (or list which tools are present/missing):

```
# paste output here
```

## Config (redacted)

Paste your `~/.beacon/config.yaml` with all API keys and secrets removed:

```yaml
# paste redacted config here
```

## Additional context

Any other context: network conditions (corporate proxy, VPN), whether you are using remote mode (`--server`), whether the issue is reproducible with a different domain, etc.
