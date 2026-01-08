#!/bin/bash
# Pre-commit checks for url_jail
# Install: ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit

set -e

echo "🔍 Running pre-commit checks..."

# Ensure Cargo.lock is in sync
echo "🔒 Checking Cargo.lock..."
cargo check --locked --features fetch,tracing 2>/dev/null || {
    echo "❌ Cargo.lock is out of sync. Run: cargo update"
    exit 1
}

# Rust checks
echo "📦 Rust format..."
cargo fmt --check

echo "📎 Rust clippy..."
cargo clippy --features fetch,tracing -- -D warnings

echo "🧪 Rust tests..."
cargo test --features fetch,tracing

# Python checks (if venv exists)
if [ -d ".venv" ]; then
    echo "🔨 Rebuilding Python bindings..."
    source .venv/bin/activate
    maturin develop --features python,fetch 2>/dev/null
    
    echo "🐍 Python tests..."
    PYTHONPATH="${PYTHONPATH}:./python" python3 -m pytest tests/ --tb=short -q
fi

echo "✅ All checks passed!"

