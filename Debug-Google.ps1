# PowerShell script to debug mpw with "google" as the first parameter
Write-Host "Starting mpw with 'google' parameter..." -ForegroundColor Green

# Set environment variables for better debugging
$env:RUST_BACKTRACE = "full"
$env:RUST_LOG = "debug"

# Build the project in debug mode if needed
Write-Host "Building project..." -ForegroundColor Yellow
cargo build

# Run the program with "google" as the first parameter
# Additional parameters can be passed from command line
Write-Host "Running mpw with parameters: google $args" -ForegroundColor Cyan
cargo run -- google $args

Write-Host "Debug session completed" -ForegroundColor Green