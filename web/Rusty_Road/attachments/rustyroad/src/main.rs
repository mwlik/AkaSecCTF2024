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
use std::sync::Mutex;
use bcrypt::{hash, verify, DEFAULT_COST};

lazy_static! {
    static ref SECRET: String = {
        let secret: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        secret
    };

    static ref ADMIN_PASSWORD: String = "M07H4F7H38167Hr33175JU57816M3".to_string();

    static ref FLAG: String = "AKASEC{W311_17_41n7_7h47_2u57yyy_4f732_411}".to_string();

    static ref USERS: Mutex<Vec<User>> = Mutex::new(vec![
        User {
            username: "admin".to_string(),
            password: hash_password(&ADMIN_PASSWORD),
        }
    ]);
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

#[derive(Debug)]
struct User {
    username: String,
    password: String,
}

fn add_user(username: &str, password: &str) {
    println!("{:?}", USERS.lock().unwrap());
    USERS.lock().unwrap().push(User {
        username: username.to_string(),
        password: password.to_string(),
    });
    println!("{:?}", USERS.lock().unwrap());
}

fn validate_token(token: &str) -> Result<TokenData<Claims>> {
    let decoding_key = DecodingKey::from_secret(SECRET.as_ref());
    decode::<Claims>(token, &decoding_key, &Validation::new(Algorithm::HS256))
}

fn subs(input: String) -> String {
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

    let username = subs(form.username.clone());
    if username.contains("admin") || username.contains(ADMIN_PASSWORD.as_str()) {
        return Redirect::to("/register");
    }

    let password = subs(form.password.clone());
    let password = hash_password(&password);

    //println!("{:?}, {:?}", username, password);
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
    let username = subs(form.username.clone());
    let password = subs(form.password.clone());

    let users_lock = USERS.lock().unwrap();

    let user = users_lock.iter().find(|user| user.username == username);
    if let Some(user) = user {
        println!("{:?}", username);
        println!("{:?}", password);
        println!("{:?}", users_lock);
        if verify(&password, &user.password).unwrap() {
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
                format!("Hello {}", data.claims.username)
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

#[get("/flag")]
fn flag(cookies: &CookieJar<'_>) -> String {
    let token = cookies.get("token").map(|cookie| cookie.value()).unwrap_or("");
    match validate_token(token) {
        Ok(data) => {
            if data.claims.user_type == "admin" {
                FLAG.clone()
            } else {
                "Access Denied".to_string()
            }
        },
        Err(_) => "Unauthorized".to_string(),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![register_form, register, home, flag, login_form, login])
}
