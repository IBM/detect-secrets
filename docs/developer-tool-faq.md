# FAQs (Detect Secrets Suite - Developer tool)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

-   [pip setup](#pip-setup)
    -   [I’m getting a `Could not install packages due to an Environment Error: [Errno 13] Permission denied: ` error when installing the `detect-secrets` pip package. What should I do?](#im-getting-a-could-not-install-packages-due-to-an-environment-error-errno-13-permission-denied--error-when-installing-the-detect-secrets-pip-package-what-should-i-do)
    -   [I cannot find the `detect-secrets` binary after installation](#i-cannot-find-the-detect-secrets-binary-after-installation)
    -   [How do I upgrade `detect-secrets` to a newer version?](#how-do-i-upgrade-detect-secrets-to-a-newer-version)
        -   [Upgrade for user mode](#upgrade-for-user-mode)
        -   [Upgrade for global mode - keep install to global mode](#upgrade-for-global-mode---keep-install-to-global-mode)
        -   [Upgrade for global mode - Switch to user mode](#upgrade-for-global-mode---switch-to-user-mode)
    -   [How do I upgrade the `detect-secrets` pre-commit hook?](#how-do-i-upgrade-the-detect-secrets-pre-commit-hook)
-   [General usage](#general-usage)
    -   [Which python versions does detect-secrets support?](#which-python-versions-does-detect-secrets-support)
    -   [How do I generate a baseline file?](#how-do-i-generate-a-baseline-file)
    -   [How do I re-generate (update) my baseline file?](#how-do-i-re-generate-update-my-baseline-file)
    -   [How do I audit my baseline file?](#how-do-i-audit-my-baseline-file)
    -   [When would fixed entries be removed from my baseline file?](#when-would-fixed-entries-be-removed-from-my-baseline-file)
    -   [Will `detect-secrets` find tokens in git history?](#will-detect-secrets-find-tokens-in-git-history)
    -   [What kind of tokens does detect-secrets find?](#what-kind-of-tokens-does-detect-secrets-find)
    -   [Why is the Slack webhook also considered as secret?](#why-is-the-slack-webhook-also-considered-as-secret)
    -   [Which plugins are being used in scan by default?](#which-plugins-are-being-used-in-scan-by-default)
    -   [How do I use fewer plugins to scan?](#how-do-i-use-fewer-plugins-to-scan)
    -   [`detect-secrets` generates too many false positives. What should I do?](#detect-secrets-generates-too-many-false-positives-what-should-i-do)
        -   [Exclude some files with the `—exclude-files` option.](#exclude-some-files-with-the-exclude-files-option)
        -   [Tune the threshold for entropy based scanner](#tune-the-threshold-for-entropy-based-scanner)
        -   [Use fewer scanners](#use-fewer-scanners)
    -   [Why did `detect-secrets` not find some secrets in my code?](#why-did-detect-secrets-not-find-some-secrets-in-my-code)
        -   [Cause 1: Not using all plugins](#cause-1-not-using-all-plugins)
        -   [Cause 2: Verifiable token is verified as false](#cause-2-verifiable-token-is-verified-as-false)
        -   [Cause 3: Entropy threshold is too high for entropy based plugins](#cause-3-entropy-threshold-is-too-high-for-entropy-based-plugins)
        -   [Cause 4: Unsupported token type](#cause-4-unsupported-token-type)
    -   [Why is the `detect-secrets` pre-commit output messed up with multiple headings and footers?](#why-is-the-detect-secrets-pre-commit-output-messed-up-with-multiple-headings-and-footers)
    -   [How do I configure the `detect-secrets` pre-commit hook with NodeJs’s husky library?](#how-do-i-configure-the-detect-secrets-pre-commit-hook-with-nodejss-husky-library)
    -   [How do I use inline allowlisting?](#how-do-i-use-inline-allowlisting)
    -   [Why does my scan get stuck](#why-does-my-scan-get-stuck)
    -   [Can I use detect-secrets to detect secrets in an arbitrary file system/folder that is not a git repo?](#can-i-use-detect-secrets-to-detect-secrets-in-an-arbitrary-file-systemfolder-that-is-not-a-git-repo)
    -   [Why is detect-secrets not verifying my password on DB2 for zOS?](#why-is-detect-secrets-not-verifying-my-password-on-db2-for-zos)
        -   [Missing certificates (known limitation)](#missing-certificates-known-limitation)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# pip setup

## I’m getting a `Could not install packages due to an Environment Error: [Errno 13] Permission denied: ` error when installing the `detect-secrets` pip package. What should I do?

This is normally caused by `pip` trying to add the package to system folders to which the current user does not have write permission. You can try to add the `--user` option to `pip install` like below

```sh
pip install --user git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

If adding `--user` does not resolve the issue, there are some cases where backlevel `pip` can cause a permission issue. In this case, please upgrade `pip`:

```sh
pip install --user --upgrade pip
```

Then perform the `detect-secrets` install again.∂

## I cannot find the `detect-secrets` binary after installation

By default, the tool will be installed at `~/Library/Python/<python_version>/bin/detect-secrets` on Mac (similar directory on Linux). If you cannot find detect-secrets, you can add the installation bin directory to your PATH by running `export PATH=$PATH:~/Library/Python/<python_version>/bin`

## How do I upgrade `detect-secrets` to a newer version?

`detect-secrets` can be installed in either `user` mode or `global` mode. You can run the one liner below to identify where `detect-secrets` is installed.

```sh
if pip list | grep detect-secrets > /dev/null ; then echo "Installed with global mode, no need to use '--user' during upgrade"; elif pip list --user | grep detect-secrets > /dev/null; then echo "Installed with user mode, use '--user' during upgrade"; else echo "Did not installed before, use '--user'"; fi
```

#### Upgrade for user mode

If detect-secrets was installed in user mode previously, keep using --user param in the upgrade command below.

```sh
pip install --upgrade --user git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

If detect-secrets was installed in global mode previously, either keep the install to global mode or switch to user mode.

#### Upgrade for global mode - keep install to global mode

```sh
pip install --upgrade git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

#### Upgrade for global mode - Switch to user mode

```sh
pip uninstall detect-secrets
pip install --upgrade --user git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets
```

If you cannot find `detect-secrets` after upgrading, read [here](#i-can-not-find-the-detect-secrets-binary-after-installation) to setup the path.

> Note: if you install `detect-secrets` as pre-commit hook, you should also [upgrade it in `pre-commit` framework](#how-do-i-upgrade-the-detect-secrets-pre-commit-hook).

## How do I upgrade the `detect-secrets` pre-commit hook?

> Note: `autoupdate` only scans for tags on master branch. It does **not** supported dss branch now. Before dss has been released onto master branch, please use specific version tag such as `rev: 0.13.0+ibm.7.dss` in `.pre-commit-config.yaml` to get latest dss version.

`pre-commit` framework manages its own copy of `detect-secrets` tool. To upgrade it you need to

```sh
cd <your_repo_have_pre_commit_configured>
pre-commit autoupdate
# The rev field for detect-secrets in .pre-commit-config.yaml will get update
# if the newest tag on master branch is differnt from the value in current rev field.
# You should commit and check in the updated file once it's been updated.
```

If the steps above do not work, you can also update pre-commit to a newer version, then clean up pre-commit cache then autoupdate again.

```sh
pip install --upgrade pre-commit -y
pre-commit clean
pre-commit gc
pre-commit autoupdate
```

# General usage

## Which python versions does detect-secrets support?

The tool supports Python 2.7, Python 3.5 and above now. But since Python 2 reached end of life on Jan 1st, 2020, we will no longer support Python 2 after July 1st, 2020.

You can follow guide [here](https://docs.python-guide.org/starting/installation/) to properly setup Python 3 env.

> Note: If you are using macOS, the default installed Python is 2, please make sure you follow the guide above to properly install Python 3.

## How do I generate a baseline file?

```shell
detect-secrets scan --update <baseline>
```

## How do I re-generate (update) my baseline file?

```shell
detect-secrets scan --update <baseline_file> <optional --no-xxx-scan or --use-all-plugins to adjust scan plugin list>
```

## How do I audit my baseline file?

-   Audit entries which do not have the `is_secret` field with `detect-secrets audit <baseline>`

## When would fixed entries be removed from my baseline file?

-   `detect-secrets scan --update <baseline_file>` would clean up old entries.
-   Once you have the pre-commit hook configured, if there are no new issues found, the pre-commit hook will clean up old (remediated) entries from baseline file. You can also manually trigger this process by running `detect-secrets-hook --baseline <baseline> <changed_file>`. If the pre-commit check fails, the baseline file will not be updated.

## Will `detect-secrets` find tokens in git history?

No, by default the `detect-secrets` CLI tool only scans the code in current commit.

## What kind of tokens does detect-secrets find?

Our developer tool uses the following plugins by default:

Supports verification

-   AWS Key
-   Slack
-   Artifactory
-   Box
-   Cloudant
-   DB2
-   Github
-   IBM Cloud IAM
-   IBM COS HMAC
-   SoftLayer
-   Stripe
-   Mailchimp

Does not support verification

-   Private Key Detector
-   Basic Auth Detector
-   Base64 High Entropy String
-   Hex High Entropy String
-   Keyword Detector
-   JSON Web Token

If you wish, check out our [plugin folder](https://github.com/IBM/detect-secrets/tree/master/detect_secrets/plugins) for more details about what we scan.

## Why is the Slack webhook also considered as secret?

Based on Slack doc below, incoming webhook should be considered as secret <https://api.slack.com/messaging/webhooks>.

> Keep it secret, keep it safe. Your webhook URL contains a secret. Don't share it online, including via public version control repositories. Slack actively searches out and revokes leaked secrets.

## Which plugins are being used in scan by default?

-   All plugins will be used when not reading config from existing baseline.
-   When using `--update <baseline>` option with exisitng baseline, the tool will use only the plugins listed in the baseline. Use `--use-all-plugins` along with `--update <baseline>` to force using all plugins.

## How do I use fewer plugins to scan?

You can use the `--use-all-plugins` and `--no-xxx-scan` options (replace `xxx` with plugin name, use `detect-secrets scan --help` to list out the options) to customize the plugin list. The added plugins would be persisted in the baseline file. If you use `-—update <baseline>` in `detect-secrets` or `--baseline <baseline>` in `detect-secrets-hook` to run a scan without additional options, the plugins used will be read from the baseline file.

Example: `detect-secrets scan --update .secrets.baseline --use-all-plugins`

## `detect-secrets` generates too many false positives. What should I do?

If the false positive hits are overwhelming, before you turning off the check, you can tune the tool in several ways:

#### Exclude some files with the `—exclude-files` option.

Detect Secrets supports regex based file and folder exclusion. The excludes file list will be recorded in the output baseline file. In future scans, if no `--exclude-files` option is provided, the existing exclude list in baseline file will be respected. If a new exclude list is supplied through the command line, it will overwrite the exclude list in the baseline file.

```sh
detect-secrets scan --exclude-files '<folder_to_ignore>|<file_to_ignore>'
```

#### Tune the threshold for entropy based scanner

-   Entropy based scanning can be tricky to tune. It depends on your project, so you might want to try detect-secrets scan several times to strike the right balance between the number of legit secrets versus false positives.
-   There are two types of entropy based scans, hex and base64. Each of them has a different character set. You can use either --base64-limit or --hex-limit with a new limit.
-   All future scans need to use the same limit number in command line, otherwise default value will overwrite the setting in the baseline file. You can specify these options in `.pre-commit-config.yaml` to make your pre-commit hook always use same options.

```sh
detect-secrets scan --base64-limit <new_limit>
# or
detect-secrets scan --hex-limit <new_limit>
```

#### Use fewer scanners

-   `--no-<scan_type>-scan` option can be used to exclude certain types of scanning. Use `detect-secrets scan —help` to view more options.
-   All future scans need to use the same no scan options in command line, otherwise the default value will overwrite the setting in the baseline file. You can specify these options in `.pre-commit-config.yaml` to make your pre-commit hook always use same options.
-   By default, all plugins are used.
-   To disable all entropy based scanning, use the command below

```sh
detect-secrets scan --no-base64-string-scan --no-hex-string-scan
```

## Why did `detect-secrets` not find some secrets in my code?

There are several different causes. Many of them are by design and intended to avoid false positives. These behaviors can be adjusted.

#### Cause 1: Not using all plugins

Developer tool uses all plugins by default. But if a baseline file is used (with `--update OLD_BASELINE_FILE` for scan, and `--baseline BASELINE` for pre-commit hook), the scan will respect the plugin list in the baseline and only use the plugins specified in the baseline.

You can use `--use-all-plugins` option to mandate scan using all plugins. The `--use-all-plugins` option is available in both scan and pre-commit hook.

#### Cause 2: Verifiable token is verified as false

Developer tool would verify [some verifiable token types](#what-kind-of-tokens-does-detect-secrets-find) by default. It means when a potential token is found, the tool will use the token to test against target service.

-   If the verification result is true or unable to verify, the potential token will be kept in scan result.
-   If the verification result is false, then the token will be left out of the scan result. This is intended to reduce false positive so only valid tokens are being reported.

You can turn off the verification behavior with `--no-verify` flag. This option is available in both scan and pre-commit hook.

#### Cause 3: Entropy threshold is too high for entropy based plugins

Tune entropy to a lower value following doc [tune the threshold for entropy based scanner](#tune-the-threshold-for-entropy-based-scanner) could yield more tokens been caught.

#### Cause 4: Unsupported token type

This can happen if the signature of one token type is not supported by detect-secrets tool. You can contribute a new token type following the guide [here](https://github.com/IBM/detect-secrets/blob/master/CONTRIBUTING.md#process-for-adding-a-new-secret-detector-to-whitewater-detect-secrets)

## Why is the `detect-secrets` pre-commit output messed up with multiple headings and footers?

A usual pre-commit scan output looks like below. The potential secrets warning heading is printed first, then followed by found secret type and locations, then the possible mitigations footer.

```shell
Potential secrets about to be committed to git repo! Please rectify or
explicitly ignore with an inline `pragma: allowlist secret` comment.

Secret Type: DB2 Credentials
Location:    myfile/something.java:80

Possible mitigations:

  - For information about putting your secrets in a safer place,
    please ask in #security
  - Mark false positives with an inline `pragma: allowlist secret`
    comment
  - Commit with `--no-verify` if this is a one-time false positive

If a secret has already been committed, visit
https://help.github.com/articles/removing-sensitive-data-from-a-
repository
```

If you are seeing the headings and footers are printed multiple times, along with reporting of token locations injected between lines, then you are running into the issue described by this question.

The reason behind this is the pre-commit framework's default parallel execution optimization. pre-commit scans all files in git staging area upon commit creation, or all files managed by git if `--all-files` option is used. To speed up the scan, pre-commit would split all the files to be scan into multiple groups, and fires up multiple threads to run the scan concurrently. The number of threads is up to the total number of CPU cores. Each individual thread would output the result without coordination which leads to the messed up output. This only happens when many files are been feed into pre-commit, such as when your commit contains a lot of changed files or you are using the `--all-files` option.

To avoid messed up output, you can add `require_serial: true` option to `pre-commit-config.yaml` like below. It will still output headings and footers multiple times, but each thread's output would be in sequence. Be careful though, using serial execution might increase the total scan time.

```yaml
- repo: local
  hooks:
      - id: <hook_id>
        # other hook config here...
        require_serial: true
```

## How do I configure the `detect-secrets` pre-commit hook with NodeJs’s husky library?

If you are using the [husky](https://github.com/typicode/husky) library to manage the pre-commit hook, you can use the snippet below in your `package.json` to properly invoke `detect-secrets-hook`. The main problem is that detect-secrets-hook is expecting a list of files in the git staging area. husky is not feeding the file list to the pre-commit hook line as a parameter. The following setting will manually generate the list of staged files.

```json
  "husky": {
    "hooks": {
      "pre-commit": "detect-secrets-hook --baseline .secrets.baseline $(git diff --cached --name-only)"
    }
  }
```

## How do I use inline allowlisting?

The tool supports the following inline allowlisting syntax.

> **Note: a space is needed between original line content and comment**

```bash
secret # pragma: allowlist secret
secret // pragma: allowlist secret
secret /* pragma: allowlist secret */
secret ' pragma: allowlist secret
secret -- pragma: allowlist secret
secret <!-- pragma: allowlist secret -->
secret <!-- # pragma: allowlist secret -->
```

## Why does my scan get stuck

There are most likely is some big text files causing the scan to run very slowly and makes user feel like the scan is stuck. You can find these offending files and exclude them from scanning.

To find out the offending file, run scan with `--verbose` option like below

```bash
detect-secrets --verbose scan <file_or_folder_to_scan>
```

The command above would emit which is the file currently under scan. Once you've identified the file, you can use `--exclude-lines` option to skip the offending files.

## Can I use detect-secrets to detect secrets in an arbitrary file system/folder that is not a git repo?

Yes.

To scan arbitrary files

```bash
detect-secrets scan <file_1> <file_2>
```

To scan an arbitrary folder, you should use the `scan --all-files` option

```bash
 detect-secrets scan --all-files <folder_name>
```

## Why is detect-secrets not verifying my password on DB2 for zOS?

A known case when DB2 for zOS password has not been caught is that you are missing certificates (known limitation).

#### Missing certificates (known limitation)

If your DB2 server requires keystore DB and keystash file to connect, then detect-secrets won't test the connection to
verify the token. This is known limitation. You can still run the scan with `--no-verify` flag,
it will report on the potential password string, but won't verify it against remote DB2 server.
