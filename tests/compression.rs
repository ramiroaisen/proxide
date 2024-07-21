mod common;
use common::{block_on, send};
use proxide::body::Body;

#[test]
fn compression_client_select() {
  crate::lock!("compression.yml");
  block_on(async move {
    // client select encoding
    for encoding in ["gzip", "br", "zstd", "deflate"] {
      let request = hyper::Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:20100/compression-all")
        .header("accept-encoding", encoding)
        .body(Body::empty())
        .unwrap();

      let response = send(request).await.expect("error making request (client select encoding)");
      
      assert_status!(response, OK);
      assert_header!(response, hyper::header::CONTENT_ENCODING, encoding);
    }

    for encoding in ["gzip", "br", "zstd", "deflate"] {
      let request = hyper::Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:20100/compression-all-octet-stream")
        .header("accept-encoding", encoding)
        .body(Body::empty())
        .unwrap();

      let response = send(request).await.expect("error making request (client select encoding)");
      
      assert_status!(response, OK);
      let header = response.headers().get(hyper::header::CONTENT_ENCODING);
      assert!(header.is_none() || header.unwrap() == "identity"); 
    }
  });
}

#[test]
fn compression_server_select() {
  crate::lock!("compression.yml");
  block_on(async move {
    let all_encodings = "gzip,br,zstd,deflate";
    // server select encoding
    for encoding in ["gzip", "br", "zstd", "deflate"] {
      let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:20100/compression-{encoding}"))
        .header("accept-encoding", all_encodings)
        .body(Body::empty())
        .unwrap();

      let response = send(request).await.expect("error making request (server select encoding)");
    
      assert_status!(response, OK);
      assert_header!(response, hyper::header::CONTENT_ENCODING, encoding);
    }
  })
}