# Cherry Server

A media server based on the Blossom protocol, designed to store and serve blobs of data.

> THIS SOFTWARE IS STILL UNDER DEVELOPMENT AND MIGHT CHANGE DRASTICALLY UNTIL A STABLE RELEASE IS PUBLISHED.

## Overview

Cherry Server is a Rust-based media server that uses the Blossom protocol to store and serve blobs of data. 
It stores files right to disk and stores metadata in a sqlite database.

## BUDs supported

| ID     | Status |
|--------|--------|
| BUD-01 | ✅     |
| BUD-02 | ✅     |
| BUD-03 | N/A    |
| BUD-04 | ✅     |
| BUD-05 | ❌     |
| BUD-06 | ✅     |
| BUD-08 | ❌     |


## Getting Started

To get started with Cherry Server, you'll need to ensure that Rust is installed on your system. Then:

### Build
```
git clone https://github.com/0xtrr/cherry-server
cd cherry-server
cargo build --release
```

### Configuration

Cherry Server can be configured using a TOML file. It defaults to the current directory and the filename config.toml
but this can be overridden by setting the "-c" flag to where the config file is placed. Remember to set this 
to the full path of the file including the filename, e.g. `/etc/cherryserver/config.toml`.

The example configuration file has set some standard default values but can be configured as you want. The file contains
a bunch of comments documenting each section and some of the fields.

### Run

```
cp example-config.toml config.toml
./target/release/cherry-server
```

## Contributing

I welcome contributions to Cherry Server! If you're interested in contributing, please fork the repository and submit a
pull request. Creating issues if you want a feature or need to report a bug/security issue is also very much appreciated!

## License

Cherry Server is licensed under the MIT License.

## Acknowledgments

Cherry Server is based on the Blossom protocol, which was designed and implemented by [hzrd149](https://github.com/hzrd149).
