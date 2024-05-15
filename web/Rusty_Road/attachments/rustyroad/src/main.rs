#[macro_use] extern crate rocket;

use rocket::form::Form;
use rocket::http::ContentType;
use rocket::response::Redirect;
use serde::Deserialize;
use serde::Serialize;
use jsonwebtoken::{encode, Header, EncodingKey, decode, Validation, Algorithm, DecodingKey, TokenData};
use jsonwebtoken::errors::Result;
use rand::Rng;
use rand::distributions::Alphanumeric;
use lazy_static::lazy_static;
use rocket::http::Cookie;
use rocket::http::CookieJar;
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex::encode as hex_encode;
use std::sync::Mutex;
use bcrypt::{hash, DEFAULT_COST};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

lazy_static! {
    static ref SECRET: String = {
        let secret: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        secret
    };

    static ref USERS: Mutex<Vec<User>> = Mutex::new(vec![
        User {
            username: "admin".to_string(),
            password: ADMIN_PASSWORD.clone(),
        }
    ]);

    // TODO: REPLACE THE BELOWW SECRET DATA WHEN GIVING THE ATTACHMENTS

    static ref ADMIN_PASSWORD: String = hash_password("M07H4F7H38167Hr33175JU57816M3");

    static ref AES_KEY: [u8; 16] = [0xf0, 0xb1, 0x02, 0xe3, 0x04, 0x05, 0xa6, 0x07, 0x08, 0x99, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    static ref AES_IV: [u8; 16] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x06, 0x17, 0x18, 0xf9, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    username: String,
    user_type: String,
    exp: usize,
}

#[derive(FromForm)]
struct RegisterForm {
    username: String,
    password: String,
}

struct User {
    username: String,
    password: String,
}

fn add_user(username: &str, password: &str) {
    USERS.lock().unwrap().push(User {
        username: username.to_string(),
        password: password.to_string(),
    });
}

fn validate_token(token: &str) -> Result<TokenData<Claims>> {
    let decoding_key = DecodingKey::from_secret(SECRET.as_ref());
    decode::<Claims>(token, &decoding_key, &Validation::new(Algorithm::HS256))
}

fn encrypt(secret: &str) -> String {
    let cipher = Aes128Cbc::new_from_slices(&AES_KEY.as_slice(), &AES_IV.as_slice()).unwrap();
    let cipher_text = cipher.encrypt_vec(secret.as_bytes());
    hex_encode(&cipher_text)
}

fn decrypt(secret: &str) -> String {
    let cipher = Aes128Cbc::new_from_slices(&AES_KEY.as_slice(), &AES_IV.as_slice()).unwrap();
    let cipher_text = hex::decode(secret).unwrap();
    let decrypted = cipher.decrypt_vec(&cipher_text).unwrap();
    String::from_utf8(decrypted).unwrap()
}

fn template(input: String) -> String {
    input.replace("ADMIN_PASSWORD", &ADMIN_PASSWORD)
}

fn hash_password(password: &str) -> String {
    hash(password, DEFAULT_COST).unwrap()
}

#[get("/register")]
fn register_form() -> (ContentType, &'static str) {
    (ContentType::HTML, "<form method='POST' action='/register'>
        <input type='text' name='username' placeholder='Username'>
        <input type='password' name='password' placeholder='Password'>
        <input type='submit' value='Register'>
    </form>")
}

#[post("/register", data = "<form>")]
fn register(form: Form<RegisterForm>, cookies: &CookieJar<'_>) -> Redirect {

    let username = template(form.username.clone());
    if username.contains("admin") || username.contains(ADMIN_PASSWORD.as_str()) {
        return Redirect::to("/register");
    }

    let password = template(form.password.clone());
    let password = hash_password(&password);

    add_user(&username, &password);

    let claims = Claims {
        username: form.username.clone(),
        user_type: "user".to_string(),
        exp: 10000000000,
    };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET.as_ref())).unwrap();

    cookies.add(Cookie::new("token", token.clone()));

    Redirect::to("/")
}

#[get("/login")]
fn login_form() -> (ContentType, &'static str) {
    (ContentType::HTML, "<form method='POST' action='/login'>
        <input type='text' name='username' placeholder='Username'>
        <input type='password' name='password' placeholder='Password'>
        <input type='submit' value='Login'>
    </form>")
}

#[post("/login", data = "<form>")]
fn login(form: Form<RegisterForm>, cookies: &CookieJar<'_>) -> Redirect {
    let username = template(form.username.clone());
    let password = template(form.password.clone());

    let users_lock = USERS.lock().unwrap();
    let user = users_lock.iter().find(|user| user.username == username);
    if let Some(user) = user {
        if hash_password(&password) == user.password {
            let user_type = if username == "admin" {
                "admin".to_string()
            } else {
                "user".to_string()
            };
            let claims = Claims {
                username: form.username.clone(),
                user_type,
                exp: 10000000000,
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET.as_ref())).unwrap();

            cookies.add(Cookie::new("token", token.clone()));

            return Redirect::to("/");
        }
    }

    Redirect::to("/login")
}

#[get("/")]
fn home(cookies: &CookieJar<'_>) -> String {
    let token = cookies.get("token").map(|cookie| cookie.value()).unwrap_or("");
    match validate_token(token) {
        Ok(data) => {
            if data.claims.user_type == "user" {
                "Hello User".to_string()
            }
            else if data.claims.user_type == "admin" {
                "Hello Admin".to_string()
            } else {
                "Access Denied".to_string()
            }
        },
        Err(_) => "Unauthorized".to_string(),
    }
}

#[get("/admin")]
fn admin(cookies: &CookieJar<'_>) -> String {
    let token = cookies.get("token").map(|cookie| cookie.value()).unwrap_or("");
    match validate_token(token) {
        Ok(data) => {
            if data.claims.user_type == "admin" {
                // THERE IS NOTHING HERE!!
                // PLEASE TRUST ME!!
                // DONT WASTE YOUR TIME!!
                // AM NOT BEING SARCASTIC!!
                // ITS NOT THAT EASY!!
                decrypt("1a29f088b6dd1238afddc786b0bf6b55169a63cb00479448e53460bd1e34b8550c23ba71ab533225f0ffe9f6912986e1b55671cb3e1f24d397057e6920478a0503eeb56fd798a69c7f4b933b78f920ad0ca2e156be96e9aeabde2f61e30a1303a956b9f422ae9d78a1b65b237b61ec34e106b4f80268a18ecfb518a2ade75fb9994d444ae73dcd04b57af017d15822d4")
            } else {
                "Access Denied".to_string()
            }
        },
        Err(_) => "Unauthorized".to_string(),
    }
}

#[launch]
fn rocket() -> _ {

    rocket::build().mount("/", routes![register_form, register, home, admin])
}