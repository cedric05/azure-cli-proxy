# Azure CLI Proxy

This is a simple proxy for Azure ARM that allows you to make REST calls without relying on `az rest` or the need for a service principal.

## How to Use

## Installation

### Cargo Install
1. Install `azure-cli-proxy` by running the following command:

    ```shell
    cargo install azure-cli-proxy

2. run `azure-cli-proxy`


### git clone

1. Clone the repository:
    ```shell
    git clone https://github.com/cedric05/azure-cli-proxy
    ```

2. Install Rust and Cargo if not already installed.

3. Build the project:
    ```shell
    cargo build --release
    ```

4. Run the proxy:
    ```shell
    ./target/release/azure-cli-proxy
    ```

## Requirements

To use the Azure CLI Proxy, you need the following:

1. Azure CLI installed.
2. Logged in to Azure via Azure CLI using the command `az login`.
3. Set the subscription using the command `az account set --name <subscription name>`.
