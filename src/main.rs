use clap::Parser;
use cli_config::{App, Commands, EncodeArgs};
use pkcs8::{Document, PrivateKeyInfo, SecretDocument};
use std::process::exit;
use translators::decode::{decode_token, print_decoded_token, OutputFormat};
use translators::encode::{encode_token, print_encoded_token};
use utils::slurp_file;

pub mod cli_config;
pub mod translators;
pub mod utils;

fn warn_unsupported(arguments: &EncodeArgs) {
    if arguments.typ.is_some() {
        println!("Sorry, `typ` isn't supported quite yet!");
    };
}

fn main() {
    let app = App::parse();
    // let matches = config_options().get_matches();

    match &app.command {
        Commands::Encode(arguments) => {
            warn_unsupported(arguments);

            let token = encode_token(arguments);
            let output_path = &arguments.output_path;

            exit(match print_encoded_token(token, output_path) {
                Ok(_) => 0,
                _ => 1,
            });
        }
        Commands::Decode(arguments) => {
            let token_data = decode_token(arguments);
            let output_path = &arguments.output_path;

            let format = if arguments.json {
                OutputFormat::Json
            } else {
                OutputFormat::Text
            };

            exit(match print_decoded_token(token_data, format, output_path) {
                Ok(_) => 0,
                _ => 1,
            });
        }
        Commands::JWK(arguments) => {
            let (_label, d) = SecretDocument::read_pem_file(&arguments.in_).unwrap();
            let p = PrivateKeyInfo::try_from(d.as_bytes()).unwrap();
            println!("{:?}", p);
            println!("a: {:?}", p.algorithm);
            match p.algorithm {
                rsa::pkcs1::ALGORITHM_ID => println!("RSA"),
                ed25519::pkcs8::ALGORITHM_ID => println!("ed25519"),
                _ => println!("Unknown"),
            }

            //let key = slurp_file(&arguments.in_);
            //let pem = crate::pem::decoder::PemEncodedKey::new(&key).unwrap();
            /*
            let decoding = DecodingKey::from_rsa_pem(&key)
                //.map_err(jsonwebtoken::errors::Error::into)
                .unwrap();
            */
            //println!("{}", serde_json::to_string(&decoding).unwrap());
        }
    };
}
