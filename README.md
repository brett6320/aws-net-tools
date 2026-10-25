# aws-reachability-analyzer

Tools for AWS VPC Reachability Analyzer and VPC IPAM.

| Tool | Description |
|---|---|
| [`tools/reachability_trace`](tools/reachability_trace/) | Create and run Reachability Analyzer traces between any supported source and destination (including across accounts), with ports applied at the source, and export them to self-contained HTML reports |
| [`tools/ipam_locate`](tools/ipam_locate/) | Find the account, Region, VPC, subnet and resource behind an IP or CIDR using IPAM, or the most specific parent pool CIDR, with an HTML report of the full hierarchy |

![Reachability trace HTML export (simulated)](tools/reachability_trace/docs/images/reachable-overview.png)

See each tool's README for usage, report formats, and IAM permissions.

## License

Free to use, modify, and redistribute. All copies and derivative works must credit the author. Commercial use while supporting clients
(consulting, contracting, managed services, and similar) requires a separate written license from the
author. See [LICENSE](LICENSE) for the full terms.
