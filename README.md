# aws-reachability-analyzer

Tools for AWS VPC Reachability Analyzer.

| Tool | Description |
|---|---|
| [`tools/reachability_trace`](tools/reachability_trace/) | Create and run Reachability Analyzer traces between any supported source and destination (including across accounts), with ports applied at the source, and export them to self-contained HTML reports |

![Reachability trace HTML export (simulated)](tools/reachability_trace/docs/images/reachable-overview.png)

See the [tool README](tools/reachability_trace/README.md) for usage, the export format, and IAM permissions.

## License

Free to use, modify, and redistribute with attribution. Commercial use while supporting clients
(consulting, contracting, managed services, and similar) requires a separate written license from the
author. See [LICENSE](LICENSE) for the full terms.
