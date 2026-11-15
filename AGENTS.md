# Agent instructions

## Commit messages

Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/#specification) for every commit. Use `<type>[optional scope][!]: <description>`; use `feat` for features and `fix` for bug fixes. Other types such as `docs`, `test`, `refactor`, `build`, and `chore` are allowed where appropriate. Mark breaking changes with `!` in the header or a `BREAKING CHANGE: <description>` footer.

## Rust build artifacts

Before running a Rust Cargo build, check, test, clippy, or similar command, check the size of the repository's `target/` directory. If it exceeds 80 GB, automatically run `cargo clean` before continuing. Do not run `cargo clean` while another Cargo process is using this repository; wait for it to finish first.
