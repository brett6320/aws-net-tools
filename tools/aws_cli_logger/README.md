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

- Bash 5.0 or later (the wrapper relies on `EPOCHREALTIME`). With an older Bash the wrapper passes commands straight through to `aws` without logging.
- AWS CLI (v1 or v2) installed somewhere on your `PATH`.
- Standard utilities: `readlink -f`, `ps`, `find`, `sort`, and `sha256sum` or `shasum`.

On macOS, `/bin/bash` is version 3.2. Install a newer one with `brew install bash` and make sure Homebrew's bin directory comes before `/bin` on your `PATH`, or change the shebang to `#!/opt/homebrew/bin/bash`.

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

All settings are optional environment variables.

| Variable | Default | Description |
|---|---|---|
| `AWS_LOG_DIR` | `~/.aws/logs` | Directory for log files |
| `AWS_LOG_KEEP_DAYS` | `30` | Delete logs older than this many days; `0` keeps everything |
| `AWS_REAL_BIN` | auto-detected | Path to the real `aws` binary, if auto-detection picks the wrong one |

## Log files

Files are named after the start of their 12-hour window:

```
~/.aws/logs/
├── aws-cli.log -> aws-cli_2026-10-30_0800.log   # symlink to the current file
├── aws-cli_2026-10-29_2000.log                   # 20:00 Oct 29 – 07:59 Oct 30
├── aws-cli_2026-10-30_0800.log                   # 08:00 – 19:59 Oct 30
└── .env-state/                                   # per-shell environment state
```

Rotation happens on demand: the first command after 08:00 or 20:00 creates the new file, moves the `aws-cli.log` symlink, and prunes files past the retention limit. A command that is still running when a window ends stays in the file it started in.

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

The wrapper's own settings (`AWS_LOG_DIR`, `AWS_LOG_KEEP_DAYS`, `AWS_REAL_BIN`) are excluded from tracking.

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

## License

Copyright (c) 2026 brett6320 (https://github.com/brett6320)

Released under the **AWS CLI Logger License**; the full text is in the header of the `aws` script.

In short: you may use, modify and redistribute it freely, provided you keep the copyright notice and license and credit the author. **Commercial use in the course of supporting clients** (consulting, contracting, managed services, audits and similar) **requires a separate written license from the author.** Personal, educational, research, non-profit, internal organizational use and evaluation are not restricted. This summary is not a substitute for the license text.
