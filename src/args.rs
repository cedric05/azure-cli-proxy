use clap::Parser;

/// Azure-Cli-proxy for proxying apis to azure arm without needing service principal client_secret
#[derive(Parser, Debug)]
#[clap(about, version, author)]
pub struct Args {
    /// proxy base addr
    /// defaults to https://management.azure.com/ can be changed to any other azure api
    /// and expects a valid azure api url without any path
    #[clap(short, long, default_value = "https://management.azure.com/")]
    pub base_addr: String,

    /// listen address
    /// defaults to 127.0.0.1:3000
    /// expects a valid ip address
    #[clap(short, long, default_value = "127.0.0.1:3000")]
    pub listen_addr: String,
}
