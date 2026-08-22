## Supported Versions

| Branch                                                                  | PHP Version | Initialization | Active Support Until | Security Support Until |
|-------------------------------------------------------------------------|-------------|----------------|----------------------|------------------------|
| [v6.1.x](https://github.com/swoole/swoole-src/tree/6.1)                 | 8.1 - 8.4   | 2025-10-24     | 2026-10-24           | 2027-04-24             |
| [v6.2.x](https://github.com/swoole/swoole-src/tree/6.2)                 | 8.2 - 8.5   | 2026-04-07     | 2027-04-07           | 2027-10-07             |
| [v6.3.x (unreleased)](https://github.com/swoole/swoole-src/tree/master) | 8.3 - 8.6   | Unreleased     | TBD                  | TBD                    |

- **Active support**： A release that is being actively supported. Reported bugs and security issues are fixed and regular point releases are made.
- **Security fixes only**:  A release that is supported for critical security issues only. Releases are only made on an as-needed basis.
- **Standard support period**: A non-LTS branch receives one year of active support followed by six months of security-only support, for a total of 1.5 years.
- **LTS support period**: A branch explicitly designated as LTS receives a total of three years of support. The active and security-only dates are listed when the LTS release is announced.

## PHP Version Support

1. Each branch (`MINOR version`) supports a fixed range of PHP versions. The `RELEASE VERSIONS` for that branch will not increase support for higher PHP versions.
2. The upper limit is four PHP versions; any additional versions will not be supported. For example, version 6.0 only supports PHP 8.1 to 8.4.
3. No support for any DEV or RC stage of PHP

The pace of PHP version updates is rapid, with each version introducing numerous underlying changes. The developers of Swoole have had to invest significant time and effort to support new releases, and we lack sufficient resources to keep up with PHP updates. Therefore, there will be a delay of one MINOR version before supporting new PHP versions.

## Unsupported Branches

> These releases that are no longer supported. Users of this release should upgrade as soon as possible, as they may be exposed to unpatched security vulnerabilities.

 
| Branch                   | PHP Version | Duration                |
|--------------------------|-------------|-------------------------|
| `1.x.x`                  | 5.4 - 7.2   | 2012-07-01 ~ 2018-05-14 |
| `2.x.x`                  | 7.0 - 7.3   | 2016-12-30 ~ 2018-05-23 |
| `4.0.x` ~ `4.3.x`        | 7.0 - 7.4   | 2018-06-14 ~ 2019-12-31 |
| `4.4.x`                  | 7.1 - 7.4   | 2019-04-15 ~ 2022-07-31 |
| `4.5.x`,`4.6.x`, `4.7.x` | 7.1 - 7.4   | 2019-12-20 ~ 2021-12-31 |
| `4.8.x`                  | 7.3 - 8.2   | 2021-10-14 ~ 2024-06-30 |
| `5.0.x`                  | 7.4 - 8.3   | 2022-01-20 ~ 2023-07-20 |
| `5.1.x`                  | 8.0 - 8.3   | 2023-11-29 ~ 2025-04-29 |
| `6.0.x`                  | 8.1 - 8.4   | 2024-12-31 ~ 2026-06-30 |
