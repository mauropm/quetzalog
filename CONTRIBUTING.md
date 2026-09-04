# Contributing to quetzalog

Thank you for your interest in contributing to quetzalog!

## Getting Started

1. **Fork** the repository and create your feature branch from `main`
2. **Clone** your fork and set up the development environment
3. Install dependencies with `make deps`

## Development Workflow

- Write tests for new features
- Follow Go conventions (gofmt, goimports)
- Run `make lint` before submitting changes
- Keep dependencies minimal
- Document API changes
- Be respectful and inclusive

## Submitting Changes

1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Run `make test` and `make lint` to ensure everything passes
4. Commit your changes (`git commit -m 'Add some feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Code Style

- Format code with `make fmt`
- Run `go vet` and `golangci-lint` before submitting
- Keep functions focused and testable
- Use meaningful variable names

## Reporting Issues

- Use the GitHub issue tracker
- Include steps to reproduce the issue
- Provide relevant logs and environment details
