#[macro_use]
extern crate lazy_static;

pub mod batch_relaying;
pub mod gravity_info;
pub mod tls;
pub mod total_suppy;
pub mod transactions;
pub mod volume;

use std::env;
use std::sync::Arc;
use std::time::Duration;

use crate::batch_relaying::generate_raw_batch_tx;
use crate::gravity_info::{
    get_erc20_metadata, get_evm_chain_configs, set_evm_chain_configs, EvmChainConfig, GravityConfig,
};
use crate::total_suppy::get_supply_info;

use crate::volume::get_volume_info;
use crate::{gravity_info::get_gravity_info, tls::*};
use actix_cors::Cors;
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use env_logger::Env;
use gravity_info::{blockchain_info_thread, get_eth_info};
use log::info;
use rocksdb::Options;
use rocksdb::DB;
use rustls::ServerConfig;
use serde::Deserialize;
use total_suppy::chain_total_supply_thread;
use transactions::database::transaction_info_thread;
use volume::bridge_volume_thread;

const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u64 = 9000;
const DEFAULT_BLOCK_PER_DAY: u64 = 7_200;
const DEFAULT_LOOP_TIME: Duration = Duration::from_secs(86400);
const DEFAULT_ETH_LOOP_TIME: Duration = Duration::from_secs(30);
const DEFAULT_PREFIX: &str = "oraib";
const DEFAULT_DENOM: &str = "uoraib";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_FINALITY_DELAY: u64 = 100;
/// number of seconds per eth block
const DEFAULT_ETH_BLOCK_TIME: u64 = 12;

#[derive(Debug, Deserialize)]
pub struct Params {
    evm_chain_prefix: String,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            evm_chain_prefix: DEFAULT_PREFIX.to_string(),
        }
    }
}

/// This is a helper api endpoint which generates an unsigned tx for a transaction batch sent from a given address
/// and returns it to the caller.
#[get("/batch_tx/{batch_nonce}")]
async fn generate_batch_tx(
    req: HttpRequest,
    gravity_config: web::Data<GravityConfig>,
    data: web::Path<(u64,)>,
) -> impl Responder {
    let params = web::Query::<Params>::from_query(req.query_string())
        .unwrap_or(web::Query(Params::default()));
    let nonce = data.into_inner().0;
    generate_raw_batch_tx(gravity_config.as_ref(), &params.evm_chain_prefix, nonce).await
}

#[get("/total_supply")]
async fn get_total_supply() -> impl Responder {
    // if we have already computed supply info return it, if not return an error
    HttpResponse::Ok().json(get_supply_info().total_supply)
}

#[get("/total_liquid_supply")]
async fn get_total_liquid_supply() -> impl Responder {
    // if we have already computed supply info return it, if not return an error
    HttpResponse::Ok().json(get_supply_info().total_liquid_supply)
}

#[get("/supply_info")]
async fn get_all_supply_info() -> impl Responder {
    // if we have already computed supply info return it, if not return an error
    HttpResponse::Ok().json(get_supply_info())
}

#[get("/eth_bridge_info")]
async fn get_eth_bridge_info(req: HttpRequest) -> impl Responder {
    let params = web::Query::<Params>::from_query(req.query_string())
        .unwrap_or(web::Query(Params::default()));
    // if we have already computed supply info return it, if not return an error
    match get_eth_info(&params.evm_chain_prefix) {
        Some(v) => HttpResponse::Ok().json(v),
        None => HttpResponse::InternalServerError()
            .json("Info not yet generated, please query in 5 minutes"),
    }
}

#[get("/gravity_bridge_info")]
async fn get_gravity_bridge_info(req: HttpRequest) -> impl Responder {
    // if we have already computed supply info return it, if not return an error
    let params = web::Query::<Params>::from_query(req.query_string())
        .unwrap_or(web::Query(Params::default()));
    match get_gravity_info(&params.evm_chain_prefix) {
        Some(v) => HttpResponse::Ok().json(v),
        None => HttpResponse::InternalServerError()
            .json("Info not yet generated, please query in 5 minutes"),
    }
}

#[get("/erc20_metadata")]
async fn erc20_metadata(req: HttpRequest) -> impl Responder {
    // if we have already computed supply info return it, if not return an error
    let params = web::Query::<Params>::from_query(req.query_string())
        .unwrap_or(web::Query(Params::default()));
    match get_erc20_metadata(&params.evm_chain_prefix) {
        Some(v) => HttpResponse::Ok().json(v),
        None => HttpResponse::InternalServerError()
            .json("Info not yet generated, please query in 5 minutes"),
    }
}

#[get("/bridge_volume")]
async fn get_bridge_volume(req: HttpRequest) -> impl Responder {
    // if we have already computed volume info return it, if not return an error
    let params = web::Query::<Params>::from_query(req.query_string())
        .unwrap_or(web::Query(Params::default()));
    match get_volume_info(&params.evm_chain_prefix) {
        Some(v) => HttpResponse::Ok().json(v),
        None => HttpResponse::InternalServerError()
            .json("Info not yet generated, please query in 20 minutes"),
    }
}

#[get("/evm_chain_prefixes")]
async fn get_evm_chain_prefixes() -> impl Responder {
    HttpResponse::Ok().json(
        get_evm_chain_configs()
            .iter()
            .map(|evm_chain| evm_chain.prefix.to_string())
            .collect::<Vec<String>>(),
    )
}

#[get("/transactions/send_to_eth")]
async fn get_all_msg_send_to_eth_transactions(db: web::Data<Arc<DB>>) -> impl Responder {
    transactions::endpoints::get_all_msg_send_to_eth_transactions(db).await
}

#[get("/transactions/ibc_transfer")]
async fn get_all_msg_ibc_transfer_transactions(db: web::Data<Arc<DB>>) -> impl Responder {
    transactions::endpoints::get_all_msg_ibc_transfer_transactions(db).await
}

#[get("/transactions/send_to_eth/time")]
async fn get_send_to_eth_transaction_totals(db: web::Data<Arc<DB>>) -> impl Responder {
    transactions::endpoints::get_send_to_eth_transaction_totals(db).await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config_path = format!(
        "{}/{}",
        env::current_dir().unwrap().display(),
        "config.yaml"
    );
    println!("{}", config_path);
    let f = std::fs::File::open(config_path)?;
    let config: serde_yaml::Value = serde_yaml::from_reader(f).unwrap();

    let evm_chains = config["evm_chains"].as_sequence().unwrap();
    let evm_chain_configs: Vec<EvmChainConfig> = evm_chains
        .iter()
        .map(|evm_chain| EvmChainConfig {
            prefix: evm_chain["prefix"].as_str().unwrap().to_string(),
            rpc: evm_chain["rpc"].as_str().unwrap().to_string(),
            finality_delay: evm_chain["finality_delay"]
                .as_u64()
                .unwrap_or(DEFAULT_FINALITY_DELAY),
            loop_time: config["eth_loop_time"]
                .as_u64()
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_ETH_LOOP_TIME),
            block_time: evm_chain["block_time"]
                .as_u64()
                .unwrap_or(DEFAULT_ETH_BLOCK_TIME),
            sender: evm_chain["sender"].as_str().unwrap().parse().unwrap(),
        })
        .collect();

    set_evm_chain_configs(evm_chain_configs);

    let gravity_config = GravityConfig {
        request_timeout: config["request_timeout"]
            .as_u64()
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        port: config["port"].as_u64().unwrap_or(DEFAULT_PORT),
        ssl: config["ssl"].as_bool().unwrap_or(false),
        host: config["host"].as_str().unwrap_or(DEFAULT_HOST).to_string(),
        prefix: config["prefix"]
            .as_str()
            .unwrap_or(DEFAULT_PREFIX)
            .to_string(),
        grpc: config["grpc"].as_str().unwrap().to_string(),
        denom: config["denom"]
            .as_str()
            .unwrap_or(DEFAULT_DENOM)
            .to_string(),
        loop_time: config["loop_time"]
            .as_u64()
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_LOOP_TIME),
        block_per_day: config["block_per_day"]
            .as_u64()
            .unwrap_or(DEFAULT_BLOCK_PER_DAY),
    };

    // starts a background thread for downloading transactions
    let mut db_options = Options::default();
    db_options.create_if_missing(true);
    let db = Arc::new(DB::open(&db_options, "transactions").expect("Failed to open database"));
    let api_db = web::Data::new(db.clone());
    transaction_info_thread(gravity_config.clone(), db.clone());

    // pass cloned structure to thread instead of moving local values
    // starts background thread for gathering into
    blockchain_info_thread(gravity_config.clone());
    // starts a background thread for generating the total supply numbers
    chain_total_supply_thread(gravity_config.clone());
    // starts a background thread for generating volume numbers
    bridge_volume_thread(gravity_config.clone());

    openssl_probe::init_ssl_cert_env_vars();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let gravity_config_data = web::Data::new(gravity_config.clone());

    let server = HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_header()
                    .allow_any_method(),
            )
            .service(get_total_supply)
            .service(get_total_liquid_supply)
            .service(get_all_supply_info)
            .service(get_eth_bridge_info)
            .service(get_gravity_bridge_info)
            .service(erc20_metadata)
            .service(get_bridge_volume)
            .service(get_evm_chain_prefixes)
            .app_data(gravity_config_data.clone())
            .app_data(api_db.clone())
            .service(get_all_msg_send_to_eth_transactions)
            .service(get_all_msg_ibc_transfer_transactions)
            .service(get_send_to_eth_transaction_totals)
            .service(generate_batch_tx)
    });

    log::info!(
        "Server start at {}:{}",
        gravity_config.host,
        gravity_config.port
    );

    let server = if gravity_config.ssl {
        let cert_chain = load_certs(&format!(
            "/etc/letsencrypt/live/{}/fullchain.pem",
            gravity_config.host
        ));
        let keys = load_private_key(&format!(
            "/etc/letsencrypt/live/{}/privkey.pem",
            gravity_config.host
        ));
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, keys)
            .unwrap();

        info!("Binding to SSL");
        server.bind_rustls(
            format!("{}:{}", gravity_config.host, gravity_config.port),
            config,
        )?
    } else {
        server.bind(format!("{}:{}", gravity_config.host, gravity_config.port))?
    };

    server.run().await?;

    Ok(())
}
