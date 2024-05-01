<div align="center">
    <img src="https://lychee.weimingchen.net:1130/uploads/original/dc/0e/eae6786c5d68d4a564f8e3f60157.png" width="100%" />
</div>

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/mlcbase)](https://pypi.org/project/mlcbase/)
[![License](https://img.shields.io/github/license/wmchen/mlcbase.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Author](https://img.shields.io/badge/author-Weiming_Chen-royalblue)](https://weimingchen.net)

</div>

## Introduction

Welcome to use MuLingCloud. We aim to let everything easier.

MLCBase is an open source Python library for multiple uses. It is the base module of all MuLingCloud modules and applications.

Supported platforms:

- 😄 Windows (Python 3.6+)
- 😄 Linux (Python 3.7+)
- MacOS (untested, maybe. I don't have a MacOS machine😫. Anyone can help me?)

<details open>
<summary>Features</summary>

- <span style="color: blue;font-weight: bold;font-style: italic">(update)</span> **Version**

    We define a `Version` class to manage the version of all MuLingCloud modules or applications. The instantiated versions can easily compare their order by using comparision operators, i.e. `==`, `!=`, `<`, `<=`, `>`, `>=`.

- **Config Dictionary**

    We define a `ConfigDict` for more convenience usage. It is a type of dictionary inherited from `dict`. It has all the features of `dict` while including other more convenient features.

- **Logger**

    We build a `Logger` for more convenience logging management. Actually, this is a slightly improvement based on [loguru](https://github.com/Delgan/loguru). Refer to [pylog](https://github.com/wmchen/pylog) for more information.

- **Runtime Analysis**

    We offer a simple way to evaluate functions in the Python project. All you need is to wrap the target function by a decorator.

- **File Operations**

    We offer various features to make file operations easier.

- <span style="color: red;font-weight: bold;font-style: italic">(new)</span> **Image IO**

    We offer a simple way to load and save images.

- <span style="color: red;font-weight: bold;font-style: italic">(new)</span> **One-Time Password**

    We support two methods for OTP: Time-based One-Time Password (TOTP) and HMAC-based One-Time Password (HOTP).

- **Encryption and Decryption**

    We offer various methods to encrypt and decrypt or verify text, files and passwords including RSA, AES and Hash.

- <span style="color: blue;font-weight: bold;font-style: italic">(update)</span> **Database**

    We offer a simple way to operate the database. Supported database backend: MySQL <span style="color: blue;font-weight: bold;font-style: italic">(update)</span>, SQLite (_doing_).

- **Remote Connection**

    We support SSH and SFTP for remote connection.

- **Email**

    We offer a simple API to send email. Currently only supports SMTP (with SSL) server.

- <span style="color: red;font-weight: bold;font-style: italic">(BREAKING CHANGE)</span> **HashiCorp Vault**

    We offer several APIs to operate [HashiCorp/Vault](https://developer.hashicorp.com/vault) through HTTP requests. Supported secret engines: KV v1, KV v2, TOTP, Transit (_doing_).

</details>

## Installation

```bash
pip install mlcbase
```

## Getting Started

Please refer to [tutorial.ipynb](./tutorial.ipynb) for more intuitive instructions.

## Changelogs

See all changes in [CHANGELOG](./CHANGELOG.md).

## Contributors

We appreciate all the contributors who add new features or fix bugs, as well as the users who offer valuable feedback.

We welcome all contributors, feel free to create an issue or file a pull request and join us! ❤️

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://weimingchen.net/"><img src="https://avatars.githubusercontent.com/u/33000375?v=4?s=100" width="100px;" alt="Weiming Chen"/><br /><sub><b>Weiming Chen</b></sub></a><br /><a href="https://github.com/wmchen/mlcbase/commits?author=wmchen" title="Code">💻</a> <a href="#ideas-wmchen" title="Ideas, Planning, & Feedback">🤔</a> <a href="#projectManagement-wmchen" title="Project Management">📆</a> <a href="https://github.com/wmchen/mlcbase/commits?author=wmchen" title="Tests">⚠️</a> <a href="#tutorial-wmchen" title="Tutorials">✅</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/dcsasori"><img src="https://avatars.githubusercontent.com/u/32105419?v=4?s=100" width="100px;" alt="dcsasori"/><br /><sub><b>dcsasori</b></sub></a><br /><a href="#ideas-dcsasori" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/wmchen/mlcbase/commits?author=dcsasori" title="Tests">⚠️</a></td>
    </tr>
  </tbody>
  <tfoot>
    <tr>
      <td align="center" size="13px" colspan="7">
        <img src="https://raw.githubusercontent.com/all-contributors/all-contributors-cli/1b8533af435da9854653492b1327a23a4dbd0a10/assets/logo-small.svg">
          <a href="https://all-contributors.js.org/docs/en/bot/usage">Add your contributions</a>
        </img>
      </td>
    </tr>
  </tfoot>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->


## License

This project is released under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).

## Repository

- Github Repository: https://github.com/wmchen/mlcbase
- Gitee Repository: https://gitee.com/wm-chen/mlcbase
