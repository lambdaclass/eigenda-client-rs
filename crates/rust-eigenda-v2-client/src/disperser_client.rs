
#[derive(Debug)]
pub struct DisperserClientConfig {
    host: String,
    port: u16,
    use_secure_grpc_flag: bool,
}


pub struct DisperserClient {
    config: DisperserClientConfig,
    
}