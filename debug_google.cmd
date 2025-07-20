@echo off
echo Starting mpw with "google" parameter...
set RUST_BACKTRACE=1
cargo run -- google %*
pause