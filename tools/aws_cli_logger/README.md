# aws-cli-logger

A drop-in wrapper for the AWS CLI that logs every `aws` command, its output, and its timing — with no change to how you use `aws`.

Each command gets a start timestamp, every line of stdout and stderr is timestamped as it arrives, and the end record captures the exit code, total duration, and when the last output arrived. Changes to `AWS_*` environment variables are tracked too. Logs roll over twice a day, at 08:00 and 20:00 local time.

## Features

- **Transparent** — output still goes to your terminal (stdout and stderr kept separate), and the real exit code is passed through, so pipes and scripts behave exactly as before.
- **Timing** — command start time, a per-line arrival timestamp (millisecond precision), the time of the last output, and the total duration.
- **8/8 rotation** — one log file per 12-hour window starting at 08:00 and 20:00, with no cron job needed.
- **Environment tracking** — logs when `AWS_PROFILE`, `AWS_REGION`, credentials and other `AWS_*` variables are set, changed, or unset. Secret values are recorded only as a short fingerprint.
- **Safe for concurrency** — each command has a random ID, so output from several terminals running at once can be separated.
- **Fails open** — if the log can't be written, `aws` still runs normally.

## Requirements

- **Bash 5.0 or later** installed somewhere on the system. It does not need to be your login shell or first on your `PATH` (see below).
- AWS CLI (v1 or v2) installed somewhere on your `PATH`.
- Standard utilities: `readlink -f` (macOS 12.3 or later), `ps`, `find`, `sort`, and `sha256sum` or `shasum`.

### Bash version and macOS

The wrapper needs Bash 5 for millisecond timestamps (`EPOCHREALTIME`), built-in date formatting and associative arrays. **macOS ships Bash 3.2.57**, which has none of these, so on a stock Mac the wrapper will run `aws` normally but **log nothing**.

Install a current Bash with Homebrew:

```zsh
brew install bash
/opt/homebrew/bin/bash --version     # should report 5.x
```

No other change is needed. Whatever shell starts the wrapper (`/bin/sh`, Bash 3.2, Bash in POSIX mode, or zsh falling back to `sh` because the shebang is missing), it looks for a Bash 5 in these locations and re-runs itself there:

1. `/opt/homebrew/bin/bash` (Homebrew on Apple silicon)
2. `/usr/local/bin/bash` (Homebrew on Intel Macs)
3. `/usr/bin/bash`
4. `/bin/bash`

If none of them is Bash 5 or later, the wrapper passes every command straight to the real `aws` without logging, so your commands never break.

## Installation

```bash
mkdir -p ~/bin
cp aws ~/bin/aws
chmod +x ~/bin/aws
```

Put `~/bin` ahead of the real AWS CLI on your `PATH`.

**Bash** (`~/.bashrc`):

```bash
export PATH="$HOME/bin:$PATH"
```

**Zsh** (`~/.zshrc`):

```zsh
path=(~/bin $path)
```

Open a new shell (in an existing zsh session, run `rehash`), then confirm the wrapper is what runs:

```bash
type -a aws        # bash
whence -va aws     # zsh
```

The wrapper should be listed first. Make sure no shell alias or function named `aws` (for example from an oh-my-zsh plugin) is shadowing it.

Tab completion keeps working, because the AWS completer calls `aws_completer` directly rather than `aws`.

## Usage

Use `aws` exactly as you normally would:

```bash
aws sts get-caller-identity
aws ec2 describe-instances --region us-east-1 --output table
aws s3 ls | grep backups
```

Follow the current log live:

```bash
tail -F ~/.aws/logs/aws-cli.log
```

Pull out everything from one command using its ID:

```bash
grep '\[3fa91c0e\]' ~/.aws/logs/aws-cli_2026-10-30_0800.log
```

## Configuration

All settings are optional environment variables. Set them with `export` in your shell profile (the wrapper runs as a separate process, so plain assignments aren't visible to it):

```zsh
export AWS_LOG_COMPRESS_DAYS=3     # gzip logs older than 3 days
export AWS_LOG_KEEP_DAYS=90        # delete logs older than 90 days
```

Ages are whole days. Compression and retention changes take effect at the next 08:00 or 20:00 rollover, and apply to all existing files.

| Variable | Default | Description |
|---|---|---|
| `AWS_LOG_DIR` | `~/.aws/logs` | Directory for log files |
| `AWS_LOG_KEEP_DAYS` | `30` | Delete logs (compressed or not) older than this many days; `0` keeps everything |
| `AWS_LOG_COMPRESS_DAYS` | `7` | Gzip logs older than this many days; `0` disables compression |
| `AWS_REAL_BIN` | auto-detected | Path to the real `aws` binary, if auto-detection picks the wrong one |

## Log files

Files are named after the start of their 12-hour window:

```
~/.aws/logs/
├── aws-cli.log -> aws-cli_2026-10-30_0800.log   # symlink to the current file
├── aws-cli_2026-10-21_0800.log.gz                # older than 7 days: compressed
├── aws-cli_2026-10-29_2000.log                   # 20:00 Oct 29 – 07:59 Oct 30
├── aws-cli_2026-10-30_0800.log                   # 08:00 – 19:59 Oct 30
└── .env-state/                                   # per-shell environment state
```

Rotation happens on demand: the first command after 08:00 or 20:00 creates the new file, moves the `aws-cli.log` symlink, and starts the compression and retention job. A command that is still running when a window ends stays in the file it started in.

### Compression and retention

At each rotation, a background job compresses logs older than `AWS_LOG_COMPRESS_DAYS` (7 by default) with `gzip -9`, then deletes logs older than `AWS_LOG_KEEP_DAYS` (30 by default), whether compressed or not. Ages are measured exactly from each file's last-modified time, and `gzip` keeps that time, so a compressed file is still deleted on schedule. The job never delays the command that triggered it, and a lock stops two shells from running it at once.

Search compressed logs directly with the `z` tools:

```bash
zgrep '\[3fa91c0e\]' ~/.aws/logs/aws-cli_*.log.gz
zcat ~/.aws/logs/aws-cli_2026-10-21_0800.log.gz | less
```

Log files are created with mode `600` and the directory with mode `700`.

## Log format

```
[2026-10-30T09:14:02.113-0400] [3fa91c0e] START shell=81 user=brett host=ws1 cwd=/home/brett profile=prod region=us-east-1 cmd: aws s3 ls
[2026-10-30T09:14:02.113-0400] [3fa91c0e] ENV changed AWS_PROFILE: dev -> prod
[2026-10-30T09:14:02.871-0400] [3fa91c0e] OUT 2026-01-04 12:00:00 my-bucket
[2026-10-30T09:14:02.880-0400] [3fa91c0e] ERR some warning
[2026-10-30T09:14:02.902-0400] [3fa91c0e] END exit=0 duration_ms=789 last_output=2026-10-30T09:14:02.880-0400
```

| Record | Meaning |
|---|---|
| `START` | Command launched. Includes the calling shell's PID, user, host, working directory, active profile and region, and the full command with shell quoting. |
| `ENV` | An `AWS_*` variable difference detected for this shell (see below). |
| `OUT` / `ERR` | One line of stdout / stderr, timestamped when the wrapper received it. |
| `END` | Command finished. `exit` is the CLI's exit code (`130` if interrupted), `duration_ms` is the total runtime, and `last_output` is the timestamp of the final line on either stream (`none` if there was no output, `n/a` for interactive commands). |

## Environment variable tracking

Each time `aws` runs, the wrapper takes a snapshot of all exported `AWS_*` variables and compares it with what the same calling shell had at its previous `aws` command.

- `ENV snapshot` — a full listing, written the first time a shell runs `aws` and again the first time it does so in a new log file, so each file stands on its own.
- `ENV set` / `ENV changed` / `ENV unset` — individual differences since that shell's last command.

Variables whose names contain `SECRET`, `TOKEN` or `PASSWORD` (such as `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`) are never logged in clear text. They appear as `<redacted sha256:xxxxxxxx len:N>`, which is enough to see that a credential changed without exposing it.

Changes are noticed when the next `aws` command runs, not at the moment of the `export`. Read an `ENV` timestamp as "changed at or before this point."

The wrapper's own settings (`AWS_LOG_*`, `AWS_REAL_BIN`) and internal markers (`AWS_WRAPPER_*`) are excluded from tracking.

## Interactive commands

Some commands need a real terminal, and piping their I/O would break them. These run directly, and only their `START` (marked `mode=interactive(output-not-captured)`) and `END` records are logged:

- `aws configure` and `aws configure sso` / `sso-session`
- `aws ssm start-session`
- `aws ecs execute-command`
- any `help` command
- auto-prompt mode (`--cli-auto-prompt` or `AWS_CLI_AUTO_PROMPT=on`)

## Security notes

- **Command output can contain secrets.** For example, `aws secretsmanager get-secret-value` and `aws sts assume-role` print sensitive values to stdout, and those lines will be written to the log. Treat the log directory accordingly.
- Credentials passed as command-line arguments (for instance `aws configure set aws_secret_access_key ...`) will appear in the `START` line.
- Environment secrets are fingerprinted, not stored, as described above.

## Limitations

- Because `aws` writes to a pipe rather than a terminal, terminal-only behavior such as colored output may not appear. The pager is disabled (`AWS_PAGER=""`) for captured commands.
- Bash reads piped input one byte at a time, so commands that produce very large output (several MB) run noticeably slower than unwrapped `aws`.
- If you press Ctrl-C, the last few lines of output may not make it into the log; the `END` record is still written with `exit=130`.

## Troubleshooting

### Nothing is being logged

The wrapper is built to fail silently, so commands keep working when logging can't. Run this to find out why:

```zsh
echo "--- which aws";      whence -va aws            # bash: type -a aws
echo "--- first line";     head -1 ~/bin/aws | od -c | head -2
echo "--- bash versions";  for b in /opt/homebrew/bin/bash /usr/local/bin/bash /bin/bash; do [ -x $b ] && echo "$b: $($b -c 'echo $BASH_VERSION')"; done
echo "--- readlink";       readlink -f ~/bin/aws
echo "--- env";            env | grep -E '^AWS_(WRAPPER|LOG_DIR|REAL_BIN)'
echo "--- log dir";        ls -la ${AWS_LOG_DIR:-~/.aws/logs}
```

| Symptom | Cause | Fix |
|---|---|---|
| Only `/bin/bash: 3.2.57` listed | No Bash 5 installed | `brew install bash` |
| Another `aws`, alias or function listed before the wrapper | Wrapper isn't what runs | Fix `PATH` order; remove the alias, function or plugin |
| `readlink` prints an error | macOS older than 12.3 | Upgrade macOS, or set `AWS_REAL_BIN` to the real CLI's path |
| `AWS_WRAPPER_ACTIVE` appears in `env` | Wrapper thinks it is already running and skips logging | `unset AWS_WRAPPER_ACTIVE` and find what exported it |
| `AWS_LOG_DIR` is set | Logs are going to that directory | Look there, or unset it |

Scripts that call the CLI by full path (for example `/usr/local/bin/aws`) bypass the wrapper entirely.

### `syntax error near unexpected token '<'`

You're running an older copy of the wrapper, which fails when started by `/bin/sh` instead of Bash. That happens when the first line isn't exactly `#!/usr/bin/env bash` (pasting can add a blank line or space before it), so zsh falls back to `sh`. The current version handles this, so replace the script with the latest one. To check the first line:

```bash
head -1 ~/bin/aws | od -c | head -2     # should start with  #   !   /   u   s   r
```

### Commands are logged twice

Two copies of the wrapper are on your `PATH`. The current version detects this and logs only once; if you see duplicates, update every copy or remove the extra one.

## License

Copyright (c) 2026 brett6320 (https://github.com/brett6320)

Released under the **AWS CLI Logger License**; the full text is in the header of the `aws` script.

In short: you may use, modify and redistribute it freely, provided you keep the copyright notice and license and credit the author. **Commercial use in the course of supporting clients** (consulting, contracting, managed services, audits and similar) **requires a separate written license from the author.** Personal, educational, research, non-profit, internal organizational use and evaluation are not restricted. This summary is not a substitute for the license text.