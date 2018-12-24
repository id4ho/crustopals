extern crate simple_server;

use self::simple_server::{Method, Server, StatusCode};
use crustopals::problem31;
use std::collections::HashMap;

pub fn run() {
  let host = "127.0.0.1";
  let port = "9000";

  let server = Server::new(|request, mut response| match request.method() {
    &Method::GET => {
      let mut query: HashMap<&str, &str> = HashMap::new();
      let query_params = request.uri().query().unwrap().split("&");
      for param in query_params {
        let key_val: Vec<&str> = param.split("=").collect();
        query.insert(key_val[0], key_val[1]);
      }
      let file = query.get("file").unwrap();
      let signature = query.get("signature").unwrap();
      let valid_sig = problem31::insecure_compare(file, signature);
      if !valid_sig {
        response.status(StatusCode::NOT_FOUND);
      }
      Ok(response.body(format!("valid: {:?}", valid_sig).as_bytes().to_vec())?)
    }
    _ => {
      response.status(StatusCode::NOT_FOUND);
      Ok(response.body("<h1>404</h1><p>Not found!<p>".as_bytes().to_vec())?)
    }
  });

  server.listen(host, port);
}
