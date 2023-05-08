use base64::prelude::BASE64_URL_SAFE_NO_PAD as b64;
use base64::Engine;
use clap::Parser;
use cli_config::{App, Commands, EncodeArgs};
use elliptic_curve::sec1::ToEncodedPoint;
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurveKeyParameters, OctetKeyPairParameters, OctetKeyPairType,
    RSAKeyParameters,
};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AssociatedOid, PrivateKeyInfo, SecretDocument};
use rsa::traits::PublicKeyParts;
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
        Commands::JWK(arguments) => {
            let (_label, d) = SecretDocument::read_pem_file(&arguments.in_).unwrap();
            println!("{_label}");
            let p = PrivateKeyInfo::try_from(d.as_bytes()).unwrap();
            let params = match p.algorithm {
                rsa::pkcs1::ALGORITHM_ID => {
                    let rsa: rsa::RsaPrivateKey = p.try_into().unwrap();
                    AlgorithmParameters::RSA(RSAKeyParameters {
                        key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                        e: b64.encode(rsa.e().to_bytes_be()),
                        n: b64.encode(rsa.n().to_bytes_be()),
                    })
                }
                ed25519::pkcs8::ALGORITHM_ID => {
                    let ed25519: ed25519::pkcs8::KeypairBytes = p.try_into().unwrap();

                    let secret = ed25519_dalek::SecretKey::from_bytes(&ed25519.secret_key).unwrap();
                    let public = ed25519_dalek::PublicKey::from(&secret);
                    AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                        key_type: jsonwebtoken::jwk::OctetKeyPairType::OctetKeyPair,
                        curve: jsonwebtoken::jwk::EllipticCurve::Ed25519,
                        x: b64.encode(public.as_bytes()),
                    })
                }
                a if a.oid == ecdsa::elliptic_curve::ALGORITHM_OID => {
                    let (curve, x, y) = match a.parameters_oid().unwrap() {
                        NistP256::OID => {
                            let n: elliptic_curve::SecretKey<NistP256> = p.try_into().unwrap();
                            let public = n.public_key();
                            let encoded = public.to_encoded_point(false);
                            (
                                jsonwebtoken::jwk::EllipticCurve::P256,
                                b64.encode(encoded.x().unwrap()),
                                b64.encode(encoded.y().unwrap()),
                            )
                        }
                        NistP384::OID => {
                            let n: elliptic_curve::SecretKey<NistP384> = p.try_into().unwrap();
                            let public = n.public_key();
                            let encoded = public.to_encoded_point(false);
                            (
                                jsonwebtoken::jwk::EllipticCurve::P384,
                                b64.encode(encoded.x().unwrap()),
                                b64.encode(encoded.y().unwrap()),
                            )
                        }
                        NistP521::OID => {
                            let n: elliptic_curve::SecretKey<NistP521> = p.try_into().unwrap();
                            let public = n.public_key();
                            let encoded = public.to_encoded_point(false);
                            (
                                jsonwebtoken::jwk::EllipticCurve::P384,
                                b64.encode(encoded.x().unwrap()),
                                b64.encode(encoded.y().unwrap()),
                            )
                        }
                        _ => {
                            println!("Unknown EC curve");
                            return;
                        }
                    };
                    AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                        key_type: jsonwebtoken::jwk::EllipticCurveKeyType::EC,
                        curve,
                        x,
                        y,
                    })
                }
                _ => {
                    println!("Unknown");
                    return;
                }
            };
            let jwk = jsonwebtoken::jwk::Jwk {
                common: Default::default(),
                algorithm: params,
            };
            println!("JWK: {}", serde_json::to_string_pretty(&jwk).unwrap());
        }
    };
}
