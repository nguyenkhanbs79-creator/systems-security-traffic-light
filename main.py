"""Entry point for the CI/CD security linter skeleton."""
import argparse


def main() -> None:
    """Parse CLI arguments and display initialization message."""
    parser = argparse.ArgumentParser(description="CI/CD Security Linter")
    parser.add_argument(
        "--workflow",
        required=True,
        help="Path to the GitHub Actions workflow YAML file",
    )
    parser.add_argument(
        "--output",
        default="report.md",
        help="Path to the output Markdown report",
    )

    args = parser.parse_args()

    print(f"Workflow path: {args.workflow}")
    print(f"Output path: {args.output}")
    print("CI/CD Security Linter skeleton initialized. Implementation will be added in later steps.")


if __name__ == "__main__":
    main()
