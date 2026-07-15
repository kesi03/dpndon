# dpndon

Dependency security scanner MCP server — wraps OSV Scanner, Trivy, and Dependency-Track behind a unified interface for LLM-powered security analysis.

## Installation

### npm (recommended)

```bash
# npm
npm install -g @mockholm/dpndon

# yarn
yarn global add @mockholm/dpndon

# pnpm
pnpm add -g @mockholm/dpndon
```

### From source

```bash
git clone https://github.com/kesi03/dpndon.git
cd dpndon
go build -o dpndon .
```

### Binary download

Download the latest binary for your platform from [GitHub Releases](https://github.com/kesi03/dpndon/releases).

### Docker

```bash
# From GitHub Container Registry
docker pull ghcr.io/kesi03/dpndon:latest

# From Docker Hub
docker pull mockholm/dpndon:latest

# Run
docker run -p 8080:8080 mockholm/dpndon
```

Or build locally:

```bash
docker build -t dpndon .
docker run -p 8080:8080 dpndon
```

Or with docker-compose:

```bash
docker compose up -d
```

The Docker image includes OSV Scanner and Trivy pre-installed. To use Dependency-Track, pass the env vars:

```bash
docker run -p 8080:8080 \
  -e DTRACK_URL=http://your-dtrack:8081 \
  -e DTRACK_API_KEY=your-key \
  mockholm/dpndon
```

With docker-compose, create a `.env` file:

```
DTRACK_URL=http://localhost:8081
DTRACK_API_KEY=your-api-key
```

Then mount your project directory to scan:

```bash
docker run -p 8080:8080 -v /path/to/project:/targets dpndon
```

## Prerequisites

dpndon shells out to external tools. Install the ones you plan to use:

| Tool | Required for | Install |
|------|-------------|---------|
| [OSV Scanner](https://github.com/google/osv-scanner) | `osv_*` tools | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| [Trivy](https://github.com/aquasecurity/trivy) | `trivy_*` tools | [trivy.dev](https://trivy.dev/latest/installation/) |
| [Dependency-Track](https://dependencytrack.org/) | `dtrack_*` tools | Docker or Kubernetes deployment |

## Usage

### Start the server

```bash
# stdio (default — for MCP clients like Claude Desktop)
dpndon serve

# SSE
dpndon serve -t sse -H 0.0.0.0 -p 8080

# Streamable HTTP
dpndon serve -t streamable-http -p 8080
```

### Configure your MCP client

Add to your MCP client config (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dpndon": {
      "command": "dpndon",
      "args": ["serve"]
    }
  }
}
```

For SSE transport:

```json
{
  "mcpServers": {
    "dpndon": {
      "url": "http://localhost:8080/sse"
    }
  }
}
```

## MCP Tools

### OSV Scanner

| Tool | Description |
|------|-------------|
| `osv_scan_source` | Scan a directory or lockfile for vulnerable dependencies |
| `osv_scan_image` | Scan a container image for vulnerabilities |
| `osv_lookup` | Look up a vulnerability by ID (e.g. GHSA-xxxx, CVE-xxxx) |

**Parameters for `osv_scan_source`:**
- `path` (required) — Path to directory or lockfile
- `recursive` — Recursively scan subdirectories (default: false)

**Parameters for `osv_scan_image`:**
- `image_name` (required) — Container image (e.g. `nginx:latest`)

**Parameters for `osv_lookup`:**
- `vuln_id` (required) — Vulnerability ID to look up

### Trivy

| Tool | Description |
|------|-------------|
| `trivy_scan_fs` | Scan filesystem for vulnerabilities, misconfigs, and secrets |
| `trivy_scan_image` | Scan a container image for vulnerabilities |
| `trivy_scan_sbom` | Analyze an SBOM file (CycloneDX/SPDX) |
| `trivy_generate_sbom` | Generate an SBOM from a project directory |

**Parameters for `trivy_scan_fs`:**
- `path` (required) — Path to scan
- `severity` — Filter: CRITICAL, HIGH, MEDIUM, LOW (comma-separated)
- `scan_types` — Types: vuln, misconfig, secret, license (comma-separated, default: vuln)

**Parameters for `trivy_scan_image`:**
- `image_name` (required) — Container image (e.g. `nginx:latest`)
- `severity` — Filter by severity

**Parameters for `trivy_scan_sbom`:**
- `sbom_path` (required) — Path to SBOM file

**Parameters for `trivy_generate_sbom`:**
- `path` (required) — Project directory to scan
- `format` — Output: `cyclonedx`, `spdx`, `spdx-json` (default: cyclonedx)

### Dependency-Track

| Tool | Description |
|------|-------------|
| `dtrack_list_projects` | List projects with vulnerability counts |
| `dtrack_list_findings` | Get findings for a specific project |
| `dtrack_search_vulnerability` | Search vulnerabilities across the portfolio |
| `dtrack_portfolio_metrics` | Get portfolio-wide security metrics |
| `dtrack_project_metrics` | Get metrics for a specific project |
| `dtrack_upload_sbom` | Upload a CycloneDX SBOM to a project |

**Environment variables (required for dtrack tools):**

```bash
export DTRACK_URL="http://localhost:8081"
export DTRACK_API_KEY="your-api-key"
```

**Parameters for `dtrack_list_projects`:**
- `query` — Filter by name
- `page` — Page number (default: 1)
- `page_size` — Results per page (default: 25)

**Parameters for `dtrack_list_findings`:**
- `project_uuid` (required) — Project UUID
- `severity` — Filter: CRITICAL, HIGH, MEDIUM, LOW

**Parameters for `dtrack_search_vulnerability`:**
- `query` (required) — CVE ID, GHSA ID, or keyword

**Parameters for `dtrack_project_metrics`:**
- `project_uuid` (required) — Project UUID

**Parameters for `dtrack_upload_sbom`:**
- `project_uuid` (required) — Target project UUID
- `sbom_path` (required) — Path to CycloneDX SBOM file
- `auto_create` — Auto-create project if missing (default: false)

## CLI Commands

```
dpndon serve      Start the MCP server
dpndon version    Print version
```

## License

MIT
