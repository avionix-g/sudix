set unstable

prep: format lint machete build test

format:
    cargo fmt
    tombi format **/Cargo.toml
    just --fmt

check-format:
    cargo fmt --check
    tombi format --check **/Cargo.toml

build:
    cargo build --all-targets

lint:
    cargo clippy --all-targets

machete:
    cargo machete

test:
    cargo test

build-release:
    cargo build --all-targets --release

# Build and install to system. Needs root.
install: build-release
    # Install binaries
    sudo install -o root -g root -m 755 target/release/sudixd /usr/bin/sudixd
    sudo install -o root -g root -m 755 target/release/sudix  /usr/bin/sudix
    sudo install -o root -g root -m 755 target/release/sudix-agent /usr/bin/sudix-agent

    # Install default config if it doesn't exist
    sudo mkdir -p /etc/sudix
    if [ ! -f /etc/sudix/policy.toml ];\
        then sudixd default-config | sudo tee /etc/sudix/policy.toml > /dev/null; fi
    sudo chown root:root /etc/sudix/policy.toml
    sudo chmod 644 /etc/sudix/policy.toml

    # Install systemd units
    sudo install -o root -g root -m 644 \
        dist/systemd/sudixd.service dist/systemd/sudixd.socket /usr/lib/systemd/system/
    sudo install -o root -g root -m 644 \
        dist/systemd/sudix-agent.service /usr/lib/systemd/user/
    sudo install -o root -g root -m 644 \
        dist/systemd/90-sudix.preset /usr/lib/systemd/user-preset/

    # Start systemd services
    sudo systemctl daemon-reload
    sudo systemctl stop sudixd.socket sudixd.service
    sudo systemctl enable --now sudixd.socket
    systemctl --user preset sudix-agent.service
    systemctl --user restart sudix-agent.service

# Uninstall from system. Needs root.
uninstall:
    # Stop systemd services
    sudo systemctl disable --now sudixd.socket sudixd.service
    systemctl --user stop sudix-agent.service

    # Remove systemd units
    sudo rm -v /usr/lib/systemd/system/sudixd.service /usr/lib/systemd/system/sudixd.socket
    sudo rm -v /usr/lib/systemd/user/sudix-agent.service
    sudo rm -v /usr/lib/systemd/user-preset/90-sudix.preset

    # Remove binaries
    sudo rm /usr/bin/sudixd
    sudo rm /usr/bin/sudix
    sudo rm /usr/bin/sudix-agent
