# Setup Linux

## Install Rust & Cargo

Just run the following command in your terminal

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build application from source

```
# Clone the repository
git clone https://github.com/0xtrr/cherry-server
# Change directory to the cloned repository
cd cherry-server
# Build from source
cargo build --release
# Add the binary to wherever you want to store it
cp target/release/cherry-server /usr/local/bin/
```

## Configurations

```
# Create a directory for the config
mkdir /etc/cherryserver
# Copy the example config into the new directory
cp example-config.toml /etc/cherryserver/config.toml
```

Then just configure it to fit your purpose. There is documentation and default values in the configuration file to help you out.

## Run the application
### Run manually
In the root of the repository folder, you can execute the following command. The `-c` flag specifies the path to the application
configuration file.

```
./target/release/cherry-server -c /etc/cherryserver/config.toml
```

### Set up as Linux service

To set up a Linux service for Cherry Server, from the root of the repository folder, run the following commands.

```
# Move the example service into the correct directory
sudo cp doc/cherry-server.service /etc/systemd/system/
```
```
# Change the contents of the service file where needed
sudo vim /etc/systemd/system/cherry-server.service
```
```
# Reload systemd, enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable cherry-server.service
sudo systemctl start cherry-server.service
```

The service and application should be up and running now. You can check the status by executing this command:
```
sudo systemctl status cherry-server.service
```

To stop or restart the service, execute one of the following commands:
```
sudo systemctl stop cherry-server.service
sudo systemctl restart cherry-server.service
```