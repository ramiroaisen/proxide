use std::time::Duration;

use common::{block_on, send};
use headers::{HeaderMapExt, Range};
use http_body_util::BodyExt;
use proxide::body::Body;
use tokio::time::sleep;

mod common;

#[test]
fn static_simple() {
  launch!("static.yml");

  block_on(async move {
    for path in ["/file.txt", "/dir/file.txt"] {
      let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:15300{path}"))
        .body(Body::empty())
        .unwrap();

      let res = send(req).await.unwrap();
      assert_status!(res, 200);
      assert_header!(res, "x-test", "static");

      let body =
        String::from_utf8_lossy(&res.into_body().collect().await.unwrap().to_bytes()).to_string();

      assert_eq!(body, "0123456789");
    }
  })
}

#[test]
fn static_dotfiles() {
  launch!("static.yml");

  block_on(async move {
    for dotfiles in ["allow", "error", "ignore"] {
      for path in ["/.dotfile.txt", "/dir/.dotfile.txt"] {
        let req = hyper::Request::builder()
          .method("GET")
          .uri(format!("http://127.0.0.1:15300{path}"))
          .header("x-dot-files", dotfiles)
          .body(Body::empty())
          .unwrap();

        sleep(Duration::from_millis(25)).await;
        let res = send(req).await.unwrap();
        let (parts, body) = res.into_parts();

        let res = hyper::Response::from_parts(parts, Body::empty());

        let body = String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).to_string();

        match dotfiles {
          "allow" => {
            assert_status!(res, 200);
            assert_eq!(body, path);
          }
          "ignore" => {
            assert_status!(res, 404);
          }
          "error" => {
            assert!(res.status().is_client_error());
          }
          _ => unreachable!(),
        }
      }
    }
  })
}

#[test]
fn static_index_files() {
  launch!("static.yml");

  let cases = [
    ("/", "/index.html"),
    ("/dir/", "/dir/index.html"),
    ("/dir2/", "/dir2/index.txt"),
  ];

  block_on(async move {
    for (path, expected) in cases {
      let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:15300{path}"))
        .body(Body::empty())
        .unwrap();

      let res = send(req).await.unwrap();
      assert_status!(res, 200);
      assert_header!(res, "x-test", "static");

      let body =
        String::from_utf8_lossy(&res.into_body().collect().await.unwrap().to_bytes()).to_string();

      log::info!("{path} -> {expected}");
      assert_eq!(body, expected);
    }
  })
}

#[test]
fn static_dir_redirect() {
  launch!("static.yml");

  block_on(async move {
    for path in ["/dir", "/dir2"] {
      let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:15300{path}"))
        .body(Body::empty())
        .unwrap();

      let res = send(req).await.unwrap();

      assert_status!(res, 302);
      assert_header!(res, "x-test", "static");
      assert_header!(res, "location", &format!("{}/", path));
    }
  })
}

#[test]
fn static_ranges() {
  launch!("static.yml");

  let cases = [
    (Range::bytes(0..), "0123456789"),
    (Range::bytes(1..), "123456789"),
    (Range::bytes(2..), "23456789"),
    (Range::bytes(3..), "3456789"),
    (Range::bytes(4..), "456789"),
    (Range::bytes(5..), "56789"),
    (Range::bytes(6..), "6789"),
    (Range::bytes(7..), "789"),
    (Range::bytes(8..), "89"),
    (Range::bytes(9..), "9"),
    (Range::bytes(0..1), "0"),
    (Range::bytes(0..=1), "01"),
    (Range::bytes(0..=2), "012"),
    (Range::bytes(0..3), "012"),
    (Range::bytes(0..4), "0123"),
    (Range::bytes(0..5), "01234"),
    (Range::bytes(0..=6), "0123456"),
    (Range::bytes(0..=7), "01234567"),
    (Range::bytes(0..=8), "012345678"),
    (Range::bytes(0..=9), "0123456789"),
    (Range::bytes(1..2), "1"),
    (Range::bytes(2..5), "234"),
    (Range::bytes(3..9), "345678"),
    (Range::bytes(4..=5), "45"),
    (Range::bytes(2..=6), "23456"),
  ];

  block_on(async move {
    for (range, expected) in cases {
      for path in ["/file.txt", "/dir/file.txt"] {
        let mut req = hyper::Request::builder()
          .method("GET")
          .uri(format!("http://127.0.0.1:15300{path}"))
          .body(Body::empty())
          .unwrap();

        sleep(Duration::from_millis(10)).await;

        req
          .headers_mut()
          .typed_insert(range.as_ref().unwrap().clone());

        let res = send(req).await.unwrap();
        assert_status!(res, 206);
        assert_header!(res, "x-test", "static");

        let body =
          String::from_utf8_lossy(&res.into_body().collect().await.unwrap().to_bytes()).to_string();

        log::info!("{path} {range:?} -> {expected}");
        assert_eq!(body, expected);
      }
    }
  })
}

// TODO: enable this test on windows
#[cfg(unix)]
#[test]
fn static_follow_symlinks() {
  launch!("static.yml");

  block_on(async move {
    let cases = [
      ("/symlink-file.txt", "0123456789"),
      ("/dir/symlink-index.html", "/dir/index.html"),
      ("/symlink-dir/index.html", "/dir/index.html"),
    ];

    for (path, expected) in cases {
      let req = hyper::Request::builder()
        .method("GET")
        .header("x-follow-symlinks", "true")
        .uri(format!("http://127.0.0.1:15300{path}"))
        .body(Body::empty())
        .unwrap();

      let res = send(req).await.unwrap();
      assert_status!(res, OK);
      assert_header!(res, "x-test-static", "follow-symlinks");
      assert_header!(res, "x-test", "static");

      let body =
        String::from_utf8_lossy(&res.into_body().collect().await.unwrap().to_bytes()).to_string();

      log::info!("{path} -> {expected}");
      assert_eq!(body, expected);
    }
  })
}

// TODO: enable this test on windows
#[cfg(unix)]
#[test]
fn static_no_follow_symlinks() {
  launch!("static.yml");

  block_on(async move {
    let cases = [
      "/symlink-file.txt",
      "/dir/symlink-index.html",
      "/symlink-dir/index.html",
    ];

    for path in cases {
      let req = hyper::Request::builder()
        .method("GET")
        .header("x-follow-symlinks", "false")
        .uri(format!("http://127.0.0.1:15300{path}"))
        .body(Body::empty())
        .unwrap();

      let res = send(req).await.unwrap();
      assert_status!(res, NOT_FOUND);
      // assert_header!(res, "x-test-static", "follow-symlinks");
      // assert_header!(res, "x-test", "static");
    }
  })
}
