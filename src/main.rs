use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use clap::{Args, Parser, Subcommand};
use pbkdf2::hmac::Hmac;
use rpassword::read_password;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
  Set(SetArgs),
  Get(GetArgs),
  List(ListArgs),
  Clone(CloneArgs),
}

#[derive(Args, Debug)]
struct SetArgs {
  /// The name of the key to store. Panics if the key already exists. Use `--force` to overwrite.
  name: String,

  /// The private key to store. If omitted, you will be prompted for it. If `silent` is true, this becomes required.
  #[arg(long, env = "KAYRING_VALUE")]
  value: Option<String>,

  #[arg(short = 'p', long, env = "KAYRING_PASSWORD")]
  password: Option<String>,

  /// Do not output logs or prompt for input. `value` becomes required.
  #[arg(short = 's', long)]
  silent: bool,

  /// Overwrite the key if it already exists.
  #[arg(short = 'f', long)]
  force: bool,

  /// Whether to echo the private key back out. Useful for initialize-and-get scenarios.
  #[arg(long)]
  echo: bool,

  /// Path to the directory where the keystores are saved
  #[arg(long, env = "KAYRING_DIR")]
  dir: Option<String>,

  /// Number of rounds to derive the encryption key. Remember this number as it is needed to retrieve the key again!
  #[arg(short, long, default_value = "100000", env = "KAYRING_DERIVATION_ROUNDS")]
  derivation_rounds: u32,
}

#[derive(Args, Debug)]
struct GetArgs {
  /// Name of the private key to retrieve.
  name: String,

  /// Encryption password. If omitted and `silent`, this will be assumed to be an empty string.
  #[arg(short = 'p', long, env = "KAYRING_PASSWORD")]
  password: Option<String>,

  /// Do not output logs or prompt for input.
  #[arg(short = 's', long)]
  silent: bool,

  /// Path to the directory where the keystores are saved
  #[arg(long, env = "KAYRING_DIR")]
  dir: Option<String>,

  /// Number of rounds to derive the encryption key. This must match the same amount used to set the key!
  #[arg(short, long, default_value = "100000", env = "KAYRING_DERIVATION_ROUNDS")]
  derivation_rounds: u32,
}

#[derive(Args, Debug)]
struct ListArgs {
  /// Path to the directory where the keystores are saved
  #[arg(long, env = "KAYRING_DIR")]
  dir: Option<String>,
}

#[derive(Args, Debug)]
struct CloneArgs {
  /// Name of the private key to clone.
  from: String,

  /// Name of the cloned private key.
  to: String,

  /// Overwrite the key if it already exists.
  #[arg(short = 'f', long)]
  force: bool,

  /// Path to the directory where the keystores are saved
  #[arg(long, env = "KAYRING_DIR")]
  dir: Option<String>,
}

fn main() {
  let cli = Cli::parse();

  let res = match cli.command {
    Commands::Set(args) => sub_set(args),
    Commands::Get(args) => sub_get(args),
    Commands::List(args) => sub_list(args),
    Commands::Clone(args) => sub_clone(args),
  };
  if let Err(e) = res {
    eprintln!("{}", e);
    std::process::exit(1);
  }
}

fn sub_set(args: SetArgs) -> Result<(), String> {
  let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
  let mut salt = [0u8; 16];
  OsRng.fill_bytes(&mut salt);
  assert!(nonce.len() == 12, "Unexpected nonce length");

  let dirpath = rootdir(args.dir)?;
  let filepath = dirpath.join(&args.name);

  if filepath.exists() && !args.force {
    return Err(format!("A kaystore {} already exists. Use --force to overwrite.", args.name));
  }

  let password = args.password.ok_or(())
    .or_else(|_| {
      if args.silent {
        Ok("".to_string())
      } else {
        let pw = promptpw("Enter password:");
        let pw2 = promptpw("Confirm password:");
        if pw != pw2 {
          Err("Passwords do not match".to_string())
        } else {
          Ok(pw)
        }
      }
    })?;

  let privkey = args.value.ok_or(())
    .or_else(|_| {
      if args.silent {
        return Err("Value is required in silent mode".to_string());
      }
      let value = promptpw("Enter value:");
      if !value.starts_with("0x") {
        return Err("Value must be a hex string starting with '0x'".to_string());
      }
      Ok(value)
    })?;
  let value = hex::decode(&privkey[2..])
    .map_err(|_| format!("Value must be a valid hex string"))?;

  if !args.silent {
    println!("Encrypting...");
  }

  let key = derive_key_v1(password, salt.as_ref(), args.derivation_rounds);
  let cipher = Aes256Gcm::new(&key.into());

  let encrypted = cipher.encrypt(&nonce, value.as_ref())
    .map_err(|err| format!("Failed to encrypt: {}", err))?;

  let contents: Vec<u8> = [
    vec![1u8], // file version 1
    salt.to_vec(),
    nonce.to_vec(),
    encrypted.to_vec()
  ].concat();

  fs::create_dir_all(dirpath.clone())
    .map_err(|err| {
      format!("Failed to create the directory at {}: {}", dirpath.to_string_lossy(), err)
    })?;

  fs::write(filepath.clone(), contents)
    .map_err(|err| {
      format!("Could not write to file {}: {}", filepath.to_string_lossy(), err)
    })?;

  if args.echo {
    println!("{}", privkey);
  }

  Ok(())
}

fn sub_get(args: GetArgs) -> Result<(), String> {
  let dirpath = rootdir(args.dir)?;
  let filepath = dirpath.join(&args.name);

  if !filepath.exists() {
    return Err(format!("No kaystore found for {}", args.name));
  }

  let password = args.password.ok_or(())
    .or_else(|_| -> Result<String, String> {
      if args.silent {
        Ok("".to_string())
      } else {
        Ok(promptpw("Enter password:"))
      }
    })?;

  let contents = fs::read(filepath.clone())
    .map_err(|err| {
      format!("Could not read from file {}: {}", filepath.to_string_lossy(), err)
    })?;

  let filever = contents[0];
  let (key, nonce, encrypted) = match filever {
    1 => (derive_key_v1(password, &contents[1..17], args.derivation_rounds), &contents[17..29], &contents[29..]),
    _ => return Err("Unknown file version".to_string()),
  };

  let cipher = Aes256Gcm::new(&key.into());
  let cleartext = cipher.decrypt(nonce.into(), encrypted)
    .map_err(|err| format!("Failed to decrypt: {}", err))?;
  let cleartext = hex::encode(cleartext);

  println!("0x{}", cleartext);

  Ok(())
}

fn sub_list(args: ListArgs) -> Result<(), String> {
  let dirpath = rootdir(args.dir)?;
  let entries = fs::read_dir(dirpath.clone())
    .map_err(|err| {
      format!("Could not read from directory {}: {}", dirpath.to_string_lossy(), err)
    })?;

  let mut has_errs = false;
  let mut results: Vec<String> = entries
    .map(|entry| -> Option<String> {
      match entry {
        Ok(entry) => Some(entry.file_name().to_string_lossy().to_string()),
        Err(_) => {
          has_errs = true;
          None
        },
      }
    })
    .filter(|entry| entry.is_some())
    .map(|entry| entry.unwrap())
    .collect();
  results.sort();

  println!("{}", results.join(", "));

  if has_errs {
    eprintln!("Some entries could not be read.");
  }

  Ok(())
}

fn sub_clone(args: CloneArgs) -> Result<(), String> {
  let dirpath = rootdir(args.dir)?;
  let frompath = dirpath.join(&args.from);
  let topath = dirpath.join(&args.to);

  if !frompath.exists() {
    return Err(format!("No kaystore found for {}", args.from));
  }

  if topath.exists() && !args.force {
    return Err(format!("A kaystore {} already exists. Use --force to overwrite.", args.to));
  }

  fs::copy(frompath.clone(), topath.clone())
    .map_err(|err| {
      format!("Could not copy from {} to {}: {}", frompath.to_string_lossy(), topath.to_string_lossy(), err)
    })?;

  Ok(())
}

fn rootdir(dir: Option<String>) -> Result<PathBuf, String> {
  dir
    .or_else(|| {
      let homedir = home::home_dir()?;
      Some(format!("{}/.kayring", homedir.to_string_lossy()))
    })
    .map(|path| Path::new(&path).to_owned())
    .ok_or_else(|| "Could not determine the root directory".to_string())
}

#[allow(dead_code)]
fn prompt(msg: impl AsRef<str>) -> String {
  use std::io::{self, Write};

  print!("{} ", msg.as_ref().trim());
  io::stdout().flush().unwrap();

  let mut input = String::new();
  io::stdin().read_line(&mut input).unwrap();

  input.trim().to_string()
}

fn promptpw(msg: impl AsRef<str>) -> String {
  use std::io::{self, Write};

  print!("{} ", msg.as_ref().trim());
  io::stdout().flush().unwrap();

  read_password().unwrap()
}

fn derive_key_v1(password: impl AsRef<str>, salt: &[u8], rounds: u32) -> [u8; 32] {
  let password = password.as_ref().nfc().collect::<String>();
  let bytes = password.as_bytes();
  let mut res = [0u8; 32];
  pbkdf2::pbkdf2::<Hmac<Sha256>>(bytes, salt, rounds, &mut res).unwrap();
  res
}
