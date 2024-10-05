<div align="center">
    <img src="https://github.com/mulingcloud/mlcbase/blob/main/static/logo_horizontal.png?raw=true" width="100%" />
</div>

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/mlcbase)](https://pypi.org/project/mlcbase/)
[![License](https://img.shields.io/github/license/wmchen/mlcbase.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![All Contributors](https://img.shields.io/github/all-contributors/wmchen/mlcbase?color=blue)](#contributors)

</div>

## Introduction

Welcome to use MuLingCloud. We aim to let everything easier.

MLCBase is an open source Python library for multiple uses. It is the base module of all MuLingCloud modules and applications.

Supported platforms:

- 😄 Windows (Python 3.6+)
- 😄 Linux (Python 3.7+)
- MacOS (untested, maybe. I don't have a MacOS machine😫. Anyone can help me?)

<details open>
<summary>Features (v1.2.2)</summary>

- **Register**

    We define a `Registry` to register modules, which allow you to use the module by a config file.

- **Config Dictionary**

    We define a `ConfigDict` for more convenience usage. It is a type of dictionary inherited from `dict`. It has all the features of `dict` while including other more convenient features.

- **Logger**

    We build a `Logger` for more convenience logging management. Actually, this is a slightly improvement based on [loguru](https://github.com/Delgan/loguru). Refer to [pylog](https://github.com/wmchen/pylog) for more information.

- **Runtime Analysis**

    We offer a simple way to evaluate functions in the Python project. All you need is to wrap the target function by a decorator.

- **Emoji Progress Bar**

    We offer a simple progress bar with emoji status. It is based on [rich](https://github.com/Textualize/rich), but with the same usage with [tqdm](https://github.com/tqdm/tqdm).

- **File Operations**

    We offer various features to make file operations easier. Besides, we offer a simple way to load and save JSON, YAML, and XML files.

- **Image IO**

    We offer a simple way to load and save images.

- **One-Time Password**

    We support two methods for OTP: Time-based One-Time Password (TOTP) and HMAC-based One-Time Password (HOTP).

- **Encryption and Decryption**

    We offer various methods to encrypt and decrypt or verify text, files and passwords including RSA, AES and Hash.

- **Database**

    We offer a simple way to operate the database. Supported database backend: MySQL, SQLite.

- **Remote Connection**

    We support SSH and SFTP for remote connection.

- **Email**

    We offer a simple API to send email. Currently only supports SMTP (with SSL) server.

- **HashiCorp Vault**

    We offer several APIs to operate [HashiCorp/Vault](https://developer.hashicorp.com/vault) through HTTP requests. Supported authorization methods: token, username & password. Supported secret engines: KV v1, KV v2, TOTP, Transit.

</details>

## Installation

```bash
pip install mlcbase -i https://pypi.org/simple
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
      <td align="center" valign="top" width="14.28%"><a href="https://www.mulingcloud.com/author/yuanshuang-sun/"><img src="https://avatars.githubusercontent.com/u/32105419?v=4?s=100" width="100px;" alt="Yuanshuang Sun"/><br /><sub><b>Yuanshuang Sun</b></sub></a><br /><a href="#ideas-dcsasori" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/wmchen/mlcbase/commits?author=dcsasori" title="Tests">⚠️</a> <a href="#tutorial-dcsasori" title="Tutorials">✅</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->


## License

This project is released under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).

## Repository

- Github Repository: https://github.com/mulingcloud/mlcbase
- GitLab Repository: https://gitlab.com/wm-chen/mlcbase
- Gitee Repository: https://gitee.com/wm-chen/mlcbase
