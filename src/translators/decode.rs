use crate::cli_config::DecodeArgs;
use crate::translators::Payload;
use crate::utils::{slurp_file, write_file, JWTError, JWTResult};
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, TokenData, Validation};
use serde_derive::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenOutput {
    pub header: Header,
    pub payload: Payload,
}

impl TokenOutput {
    fn new(data: TokenData<Payload>) -> Self {
        TokenOutput {
            header: data.header,
            payload: data.claims,
        }
    }
}

pub fn decoding_key_from_secret(alg: Algorithm, secret_string: &str) -> JWTResult<DecodingKey> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());
                Ok(DecodingKey::from_secret(&secret))
            } else if secret_string.starts_with("b64:") {
                Ok(DecodingKey::from_secret(
                    &base64_engine
                        .decode(secret_string.chars().skip(4).collect::<String>())
                        .unwrap(),
                ))
            } else {
                Ok(DecodingKey::from_secret(secret_string.as_bytes()))
            }
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            if !&secret_string.starts_with('@') {
                return Err(JWTError::Internal(format!(
                    "Secret for {alg:?} must be a file path starting with @",
                )));
            }

            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => {
                    DecodingKey::from_rsa_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
                }
                false => Ok(DecodingKey::from_rsa_der(&secret)),
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            if !&secret_string.starts_with('@') {
                return Err(JWTError::Internal(format!(
                    "Secret for {alg:?} must be a file path starting with @",
                )));
            }

            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => {
                    DecodingKey::from_ec_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
                }
                false => Ok(DecodingKey::from_ec_der(&secret)),
            }
        }
        Algorithm::EdDSA => {
            if !&secret_string.starts_with('@') {
                return Err(JWTError::Internal(format!(
                    "Secret for {alg:?} must be a file path starting with @",
                )));
            }

            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => {
                    DecodingKey::from_ed_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
                }
                false => Ok(DecodingKey::from_ed_der(&secret)),
            }
        }
    }
}

pub fn decode_token(arguments: &DecodeArgs) -> JWTResult<TokenData<Payload>> {
    let jwt = match arguments.jwt.as_str() {
        "-" => {
            let mut buffer = String::new();

            io::stdin()
                .read_line(&mut buffer)
                .expect("STDIN was not valid UTF-8");

            buffer
        }
        _ => arguments.jwt.clone(),
    }
    .trim()
    .to_owned();

    let header = decode_header(&jwt)?;
    let algorithm = header.alg;
    if let Some(alg) = arguments.algorithm {
        if algorithm != alg.into() {
            return Err(JWTError::Internal(format!(
                "Mismatched algorithm, token uses {:?}",
                header.alg
            )));
        }
    }

    let mut secret_validator = Validation::new(algorithm);
    secret_validator.leeway = 1000;

    if arguments.ignore_exp {
        secret_validator
            .required_spec_claims
            .retain(|claim| claim != "exp");
        secret_validator.validate_exp = false;
    }

    let secret_key = if arguments.secret.is_empty() {
        secret_validator.insecure_disable_signature_validation();
        secret_validator.required_spec_claims = HashSet::new();
        secret_validator.validate_exp = false;
        DecodingKey::from_secret("".as_ref())
    } else {
        decoding_key_from_secret(algorithm, &arguments.secret)?
    };

    decode::<Payload>(&jwt, &secret_key, &secret_validator)
        .map_err(jsonwebtoken::errors::Error::into)
        .map(|mut token| {
            if arguments.time_format.is_some() {
                token
                    .claims
                    .convert_timestamps(arguments.time_format.unwrap_or(super::TimeFormat::UTC));
            }

            token
        })
}

pub fn print_decoded_token(
    token_data: JWTResult<TokenData<Payload>>,
    format: OutputFormat,
    output_path: &Option<PathBuf>,
) -> JWTResult<()> {
    match token_data {
        Ok(token) => {
            if let Some(path) = output_path {
                let json = to_string_pretty(&TokenOutput::new(token)).unwrap();
                write_file(path, json.as_bytes());
                println!("Wrote jwt to file {}", path.display());
            } else if format == OutputFormat::Json {
                println!("{}", to_string_pretty(&TokenOutput::new(token)).unwrap());
            } else {
                bunt::println!("\n{$bold}Token header\n------------{/$}");
                println!("{}\n", to_string_pretty(&token.header).unwrap());
                bunt::println!("{$bold}Token claims\n------------{/$}");
                println!("{}", to_string_pretty(&token.claims).unwrap());
            }
            Ok(())
        }
        Err(JWTError::External(ext_err)) => {
            match ext_err.kind() {
                    ErrorKind::InvalidToken => {
                        bunt::println!("{$red+bold}The JWT provided is invalid {/$}")
                    }
                    ErrorKind::InvalidSignature => {
                        bunt::eprintln!("{$red+bold}The JWT provided has an invalid signature{/$}")
                    }
                    ErrorKind::InvalidRsaKey(_) => {
                        bunt::eprintln!("{$red+bold}The secret provided isn't a valid RSA key{/$}")
                    }
                    ErrorKind::InvalidEcdsaKey => {
                        bunt::eprintln!("{$red+bold}The secret provided isn't a valid ECDSA key{/$}")
                    }
                    ErrorKind::MissingRequiredClaim(missing) => {
                        if missing.as_str() == "exp" {
                            bunt::eprintln!("{$red+bold}`exp` is missing, but is required. This error can be ignored via the `--ignore-exp` parameter.{/$}")
                        } else {
                            bunt::eprintln!("{$red+bold}`{:?}` is missing, but is required{/$}", missing)
                        }
                    }
                    ErrorKind::ExpiredSignature => {
                        bunt::eprintln!("{$red+bold}The token has expired (or the `exp` claim is not set). This error can be ignored via the `--ignore-exp` parameter.{/$}")
                    }
                    ErrorKind::InvalidIssuer => {
                        bunt::println!("{$red+bold}The token issuer is invalid{/$}")
                    }
                    ErrorKind::InvalidAudience => {
                        bunt::eprintln!("{$red+bold}The token audience doesn't match the subject{/$}")
                    }
                    ErrorKind::InvalidSubject => {
                        bunt::eprintln!("{$red+bold}The token subject doesn't match the audience{/$}")
                    }
                    ErrorKind::ImmatureSignature => bunt::eprintln!(
                        "{$red+bold}The `nbf` claim is in the future which isn't allowed{/$}"
                    ),
                    ErrorKind::InvalidAlgorithm => bunt::eprintln!(
                        "{$red+bold}The JWT provided has a different signing algorithm than the one you \
                                             provided{/$}",
                    ),
                    _ => bunt::eprintln!(
                        "{$red+bold}The JWT provided is invalid because{/$} {:?}",
                        ext_err
                    ),
                };
            Err(JWTError::External(ext_err))
        }
        Err(JWTError::Internal(int_err)) => {
            bunt::eprintln!("{$red+bold}{:?}{/$}", int_err);
            Err(JWTError::Internal(int_err))
        }
    }
}
