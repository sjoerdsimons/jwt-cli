use clap::Parser;
use cli_config::{App, Commands, EncodeArgs};
use std::process::exit;
use translators::decode::{decode_token, print_decoded_token, OutputFormat};
use translators::encode::{encode_token, print_encoded_token};

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
    };
}
