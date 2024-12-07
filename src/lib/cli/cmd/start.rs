use anyhow::Context;
use indexmap::{map::Entry, IndexMap};
use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  sign::CertifiedKey,
  version::{TLS12, TLS13},
};
use std::future::Future;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
  cli::args,
  client::pool::Key,
  config::{
    self,
    defaults::{
      DEFAULT_HTTP_HEALTHCHECK, DEFAULT_HTTP_SERVER_READ_TIMEOUT,
      DEFAULT_HTTP_SERVER_WRITE_TIMEOUT, DEFAULT_PROXY_PROTOCOL_READ_TIMEOUT,
      DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT, DEFAULT_PROXY_TCP_NODELAY,
      DEFAULT_STREAM_PROXY_READ_TIMEOUT, DEFAULT_STREAM_PROXY_WRITE_TIMEOUT,
    },
    server_name::ServerName,
    Config, HttpApp, HttpHandle, StreamHandle,
  },
  net::bind,
  proxy::{
    self,
    health::{stream_upstream_healthcheck_task, upstream_healthcheck_task},
    service::ProxyStreamService,
  },
  proxy_protocol::ExpectProxyProtocol,
  serve::{serve_http, serve_https, serve_ssl, serve_tcp},
  tls::{cert_resolver::CertResolver, crypto, load_certs, load_private_key},
};

#[cfg(feature = "proctitle")]
crate::group!(
  const PROCTITLE: &str = "proxide";
  const PROCTITLE_SHUTDOWN: &str = "proxide - graceful shutdown";
);

/// This function will create a [tokio] runtime and call [start] within it. \
/// the tokio runtime can be configured with command line arguments and env variables. \
/// go to the [start] function to know more about this command.
pub fn runtime_start(args: args::Start) -> Result<(), anyhow::Error> {
  if let Some(chdir) = &args.chdir {
    std::env::set_current_dir(chdir)
      .with_context(|| format!("error setting current working directory to {}", chdir))?;
  }

  #[cfg(feature = "tracing")]
  console_subscriber::init();

  let mut runtime = tokio::runtime::Builder::new_multi_thread();

  runtime.enable_all();

  args.runtime.apply(&mut runtime);

  let runtime = runtime.build()?;

  let r = runtime.block_on(start(args));

  if let Err(e) = &r {
    if log::log_enabled!(log::Level::Error) {
      // {:#} format will print the anyhow::Error along with the chain of sources
      log::error!("{:#}", e);
      // separate the termination error message one line off the rest of the logs for better readability
      eprintln!();
    }
  }

  r
}

/// ### The proxide start command  
/// It will launch a new [instance] and start serving requets according to the config file specified, the command line arguments and the enviroment variables.
///
///
/// ### Process signals
/// The command can be controlled with process signals. \
/// **SIGINT** for graceful shutdown. \
/// **SIGTERM** for abrupt shutdown. \
/// **SIGUSR1** for configuration and certificates reload. \
///
///  
/// ### Graceful reload - SIGUSR1
/// This fn is responsible of relaunching a new [instance] every time the process receives a SIGUSR1 signal. \
/// The previous launched [instance] will be gracefully shutdown after the new instance binds to all addresses and is ready to serve requests. \
/// In case the new instance fails to start, the previous instance won't be shutted down and will continue the serve requests. \
///
/// Note that the configuration reload is done without incurring in any downtime, even if the new instance fails to start. \
///
pub async fn start(args: args::Start) -> Result<(), anyhow::Error> {
  // the following will set the title shown in the process list in several programs like top or htop. \
  // it must be called after reading the args as it override the argv memory of the process in GNU/Linux targets. \
  #[cfg(feature = "proctitle")]
  crate::proctitle::set_proctitle(PROCTITLE);

  let result: Result<(), anyhow::Error>;

  #[cfg(unix)]
  {
    use tokio::signal::unix::{signal, SignalKind};

    // listen for process signals
    let mut sigint =
      signal(SignalKind::interrupt()).context("failed to setup the SIGINT signal")?;

    let mut sigterm =
      signal(SignalKind::terminate()).context("failed to setup the SIGTERM signal")?;

    let mut sigusr1 =
      signal(SignalKind::user_defined1()).context("failed to setup the SIGUSR1 signal")?;

    // this is the current instance abort signal and abort controller
    let (mut abort, abort_recv) = tokio::sync::oneshot::channel::<()>();

    // this is the current serve handle
    let signal = async move {
      match abort_recv.await {
        Ok(_) => {}
        Err(_) => {
          // if channel is closed we do not send the shutdown signal
          futures_util::future::pending::<()>().await;
        }
      };
    };

    'start: {
      let mut handle = match instance(args.clone(), signal).await {
        Ok(handle) => handle,
        Err(e) => {
          result = Err(e);
          break 'start;
        }
      };

      result = loop {
        tokio::select! {
          // SIGTERM is used to abrupt shutdown
          _ = sigterm.recv() => {
            log::info!("received SIGTERM, abruptly shutting down (use SIGINT to shutdown gracefully)");
            break Ok(());
          }

          // SIGINT starts a graceful shutdown
          _ = sigint.recv() => {
            log::info!("received SIGINT, starting graceful shutdown");

            // change the proctitle, showing that this process is shutting down
            #[cfg(feature = "proctitle")]
            crate::proctitle::set_proctitle(PROCTITLE_SHUTDOWN);

            // send the abort signal to the current instance
            let _ = abort.send(());

            // while we are shutting down, we continue listening for SIGTERM signal to abruptly shutdown
            tokio::select! {
              // on SIGTERM we shudown the process
              _ = sigterm.recv() => {
                log::info!("received SIGTERM, abruptly shutting down");
                break Ok(());
              }

              // here the handle has finished the graceful shutdown, we return the result, propagating the panic
              r = handle => {
                break r.unwrap();
              }
            }
          }

          // on SIGUSR1 we launch a new instance, once the new instance is correctly started, we signal the old instance to gracefully shutdown
          _ = sigusr1.recv() => {
            log::info!("received SIGUSR1, starting configuration upgrade");
            let (new_abort, new_abort_recv) = tokio::sync::oneshot::channel::<()>();
            let new_signal = async move {
              let _ = new_abort_recv.await;
            };

            let new_handle = match instance(args.clone(), new_signal).await {
              Ok(handle) => handle,
              Err(e) => {
                // if the new instance fails, we do not signal the old instance to gracefully shutdown
                log::error!("error upgrading instance: {e}");
                continue;
              }
            };

            log::info!("new instance started, starting graceful shutdown of previous instance");

            // send the abort signal to the old instance
            let _ = abort.send(());

            // override the abort signal and handle of the old instance with the new ones
            abort = new_abort;
            handle = new_handle;

            continue;
          }

          result = &mut handle => {
            break result.unwrap()
          }
        }
      }
    }
  }

  #[cfg(windows)]
  {
    result = 'result: {
      // TODO: see tokio::signal::windows
      let (abort_send, abort_recv) = tokio::sync::oneshot::channel::<()>();

      let abort_signal = async move {
        match abort_recv.await {
          Ok(_) => {}
          Err(_) => futures_util::future::pending().await,
        }
      };

      let mut handle = match instance(args.clone(), abort_signal).await {
        Ok(handle) => handle,
        Err(e) => break 'result Err(e),
      };

      let mut ctrl_c =
        tokio::signal::windows::ctrl_c().with_context(|| "failed to setup Ctrl+C handler")?;

      tokio::select! {
        _ = ctrl_c.recv() => {
          #[cfg(feature = "proctitle")]
          crate::proctitle::set_proctitle(PROCTITLE_SHUTDOWN);
          log::info!("received Ctrl+C, starting graceful shutdown");
          let _ = abort_send.send(());

          tokio::select! {
            _ = ctrl_c.recv() => {
              log::info!("received second Ctrl+C, forcing shutdown");
              Ok(())
            },
            r = &mut handle => r.unwrap()
          }
        }

        r = &mut handle => r.unwrap()
      }
    };
  }

  // calling this before dropping the runtime prevents panics from
  // trying to use timers while the runtime is shutting down
  crate::log::logfile::CLIENT_LOG.cancel();
  crate::log::logfile::ACCESS_LOG.cancel();
  crate::log::logfile::PRIMARY_LOG.cancel();

  result
}

/// launch a proxide instance from cli [args::Start]. \
/// this function will read the config file given in [args::Start] and call [instance_from_config] with the parsed config. \just
pub async fn instance<F: Future<Output = ()> + Send + 'static>(
  args: args::Start,
  abort: F,
) -> Result<JoinHandle<Result<(), anyhow::Error>>, anyhow::Error> {
  let config = config::load(&args.config)
    .with_context(|| format!("error loading config file from {}", args.config))?;

  instance_from_config(args, config, abort).await
}

///  launch a proxide instance from cli [args::Start] and a parsed [Config]. \
///  this function reads certificates and keys and bind to all addresse specified in [Config].
///  it will return a [JoinHandle] once the config is loaded and all addresses are binded. \
///  it will also start the healthcheck task for each upstream. \
///  once this function returns Ok, the previous instance can be gracefully shutdown. \
///  it receives an abort Future than will start the graceful shutdown process when resolved. \  
pub async fn instance_from_config<F: Future<Output = ()> + Send + 'static>(
  args: args::Start,
  config: Config,
  abort: F,
) -> Result<JoinHandle<Result<(), anyhow::Error>>, anyhow::Error> {
  let config = Arc::new(config);

  // log level can be configured from config file or from command line (and env)
  // command line takes precedence
  let log_level = crate::option!(
    args.log_level,
    config.log_level
    => Default::default()
  );

  // this will init the logger and logfiles the first time and update the settings on later calls
  crate::log::init_or_update(
    log_level,
    config.primary_log.clone(),
    config.access_log.clone(),
    config.client_log.clone(),
  );

  log::info!("config loaded from {}", args.config);

  {
    macro_rules! limit {
      ($name:ident, $resource:ident) => {{
        let limit = crate::option!(args.rlimit.$name, config.rlimit.$name);

        if let Some(limit) = limit {
          #[cfg(unix)]
          {
            log::info!("setting rlimit {} to {}", stringify!($resource), limit);
            rlimit::setrlimit(rlimit::Resource::$resource, limit, limit).with_context(|| {
              format!(
                "error setting rlimit {} to {}",
                stringify!($resource),
                limit
              )
            })?;
          }

          #[cfg(not(unix))]
          {
            log::warn!(
              "setting process rlimits ({}, {}) is not supported on non unix platforms",
              stringify!($resource),
              limit
            );
          }
        }
      }};
    }

    limit!(nofile, NOFILE);
    limit!(nproc, NPROC);
    limit!(rthreads, THREADS);
    limit!(nthr, NTHR);
    limit!(stack, STACK);
    limit!(rss, RSS);
    limit!(r#as, AS);
    limit!(memlock, MEMLOCK);
    limit!(swap, SWAP);
    limit!(cpu, CPU);
    limit!(core, CORE);
    limit!(data, DATA);
    limit!(fsize, FSIZE);
  }

  // init jemalloc profiling
  // jemalloc profiling file can be exposed trough http with the appropriate config
  #[cfg(all(target_os = "linux", feature = "jemalloc"))]
  if crate::once!() {
    if let Some(ctl) = jemalloc_pprof::PROF_CTL.as_ref() {
      let mut ctl = ctl.lock().await;
      ctl
        .activate()
        .with_context(|| "error activating heap profiling")?;
    }
  }

  // ensure pidfile direcytory exists
  if let Some(pidfile) = &config.pidfile {
    let mut piddir = std::path::PathBuf::from(pidfile);
    piddir.pop();
    std::fs::create_dir_all(&piddir)
      .with_context(|| format!("error creating pidfile directory at {}", piddir.display()))?;
  };

  // this is the global cancel token for this instance
  // calling cancel on this token will gracefully shutdown the instance
  let cancel_token = CancellationToken::new();

  // the caller can signal the instance to gracefully shutdown
  tokio::spawn({
    let cancel_token = cancel_token.clone();
    async move {
      abort.await;
      log::info!("received instance abort, starting graceful shutdown");
      cancel_token.cancel();
    }
  });

  /*
   * this struct contains the mapping between an ssl listen port and the SNI hostnames with their respective [`CertfiedKeys`]
   */
  let mut https_bind = IndexMap::<
    SocketAddr,
    (
      Option<ExpectProxyProtocol>,
      IndexMap<ServerName, Arc<CertifiedKey>>,
    ),
  >::new();

  /*
   * the http tcp and ssl ports are simpler, we only deduplicate them
   */
  let mut http_bind = IndexMap::<SocketAddr, Option<ExpectProxyProtocol>>::new();

  /*
   * In the future we might want to support multiple ssl certificates per server with sni name in stream ssl mode
   */
  let mut stream_ssl_bind = IndexMap::<
    SocketAddr,
    (
      Vec<CertificateDer<'static>>,
      PrivateKeyDer<'static>,
      Option<ExpectProxyProtocol>,
    ),
  >::new();

  /*
   * tcp ports only need a SocketAddr
   */
  let mut stream_tcp_bind = IndexMap::<SocketAddr, Option<ExpectProxyProtocol>>::new();

  // collect all addr/port/protocol in the sets/maps (http/s)
  for app in &config.http.apps {
    for listen in &app.listen {
      for addr in listen.addr.addrs() {
        match &listen.ssl {
          None => {
            if https_bind.contains_key(&addr) {
              anyhow::bail!(
                "https and http cannot bind to same port at {} in config file",
                addr,
              );
            }

            match http_bind.entry(addr) {
              Entry::Vacant(entry) => {
                entry.insert(listen.expect_proxy_protocol);
              }

              Entry::Occupied(entry) => {
                if listen.expect_proxy_protocol != *entry.get() {
                  anyhow::bail!(
                    "expect_proxy_protocol must be the same for listen configs that share the address at {} in config file", 
                    addr,
                  );
                }
              }
            }
          }

          Some(ssl) => {
            if http_bind.contains_key(&addr) {
              anyhow::bail!(
                "https and http cannot bind to same port at {} in config file",
                addr,
              );
            }

            match https_bind.get(&addr) {
              None => {}
              Some((expect_proxy_protocol, _)) => {
                if *expect_proxy_protocol != listen.expect_proxy_protocol {
                  anyhow::bail!(
                    "expect_proxy_protocol must be the same for listen configs that share the address at {} in config file", 
                    addr,
                  );
                }
              }
            }

            let iter = match app.server_names.as_ref() {
              Some(list) => list.as_slice(),
              None => &[ServerName::All],
            };

            for server_name in iter {
              let https_hosts = &mut https_bind
                .entry(addr)
                .or_insert_with(|| (listen.expect_proxy_protocol, IndexMap::new()))
                .1;

              match https_hosts.entry(server_name.clone()) {
                Entry::Occupied(_) => {
                  anyhow::bail!(
                    "duplicate listen address + server name in config file at address: {} server name: {}",
                    addr,
                    server_name
                  );
                }

                Entry::Vacant(entry) => {
                  let certs_der = load_certs(&ssl.cert)
                    .with_context(|| format!("error loading ssl certificate at {}", ssl.cert))?;

                  let key_der = load_private_key(&ssl.key)
                    .with_context(|| format!("error loading ssl private key at {}", ssl.key))?;

                  let signing_key = crypto::sign::any_supported_type(&key_der)
                    .with_context(|| format!("crypto error at certificate key {}", ssl.key))?;

                  let certified_key =
                    Arc::new(rustls::sign::CertifiedKey::new(certs_der, signing_key));

                  entry.insert(certified_key);
                }
              }
            }
          }
        }
      }
    }
  }

  // collect all addr/port in the sets/maps (tcp/ssl)
  for stream in &config.stream.apps {
    for listen in &stream.listen {
      for addr in listen.addr.addrs() {
        match &listen.ssl {
          None => {
            let exists = https_bind.contains_key(&addr)
              || http_bind.contains_key(&addr)
              || stream_ssl_bind.contains_key(&addr)
              || stream_tcp_bind.contains_key(&addr);

            if exists {
              anyhow::bail!(
                "duplicated listen address (tcp stream) at {} in config file",
                addr,
              );
            }

            stream_tcp_bind.insert(addr, listen.expect_proxy_protocol);
          }

          Some(ssl) => {
            let exists = https_bind.contains_key(&addr)
              || http_bind.contains_key(&addr)
              || stream_ssl_bind.contains_key(&addr)
              || stream_tcp_bind.contains_key(&addr);

            if exists {
              anyhow::bail!(
                "duplicated listen address (ssl stream) at {} in config file",
                addr,
              );
            }

            let certs_der = load_certs(&ssl.cert)
              .with_context(|| format!("error loading ssl certificate at {}", ssl.cert))?;

            let key_der = load_private_key(&ssl.key)
              .with_context(|| format!("error loading ssl private key at {}", ssl.key))?;

            stream_ssl_bind.insert(addr, (certs_der, key_der, listen.expect_proxy_protocol));
          }
        }
      }
    }
  }

  // args(and env) takes precedence over config
  let http_graceful_shutdown_timeout = crate::option!(
    @duration
    args.http.http_graceful_shutdown_timeout,
    config.http.graceful_shutdown_timeout,
    args.graceful_shutdown_timeout,
    config.graceful_shutdown_timeout
  );

  // args(and env) takes precedence over config
  let stream_graceful_shutdown_timeout = crate::option!(
    @duration
    args.stream.stream_graceful_shutdown_timeout,
    config.stream.graceful_shutdown_timeout,
    args.graceful_shutdown_timeout,
    config.graceful_shutdown_timeout
  );

  // global read timeout for http(s) servers
  let http_server_read_timeout = crate::option!(
    @duration
    config.http.server_read_timeout,
    => DEFAULT_HTTP_SERVER_READ_TIMEOUT
  );

  // global write timeout for http(s) servers
  let http_server_write_timeout = crate::option!(
    @duration
    config.http.server_write_timeout,
    => DEFAULT_HTTP_SERVER_WRITE_TIMEOUT
  );

  let http_proxy_protocol_read_timeout = crate::option!(
    @duration
    config.http.proxy_protocol_read_timeout,
    config.proxy_protocol_read_timeout,
    => DEFAULT_PROXY_PROTOCOL_READ_TIMEOUT
  );

  let stream_proxy_protocol_read_timeout = crate::option!(
    @duration
    config.stream.proxy_protocol_read_timeout,
    config.proxy_protocol_read_timeout,
    => DEFAULT_PROXY_PROTOCOL_READ_TIMEOUT
  );

  // this is like a Barrier, all serve tasks will wait for this signal before start serving requests
  let (start, _) = tokio::sync::watch::channel::<()>(());

  // we collect here all tha handles for joining all of them later
  let mut handles = Vec::<tokio::task::JoinHandle<()>>::new();

  // bind to al http addresss
  for (local_addr, expect_proxy_protocol) in http_bind {
    log::info!("binding in http mode at {local_addr}");
    let tcp = bind(local_addr)
      .with_context(|| format!("error binding in http mode at addr {local_addr}"))?;

    let make_service = proxy::service::HttpMakeService::new(config.clone());

    let handle = tokio::spawn({
      let signal = cancel_token.clone().cancelled_owned();
      let mut wait_start = start.subscribe();
      async move {
        if let Ok(()) = wait_start.changed().await {
          log::info!("starting http server at {}", local_addr);

          serve_http(
            local_addr,
            tcp,
            make_service,
            signal,
            http_server_read_timeout,
            http_server_write_timeout,
            http_graceful_shutdown_timeout,
            expect_proxy_protocol,
            http_proxy_protocol_read_timeout,
          )
          .await;
        }
        log::info!("http server at {} stopped", local_addr);
      }
    });

    handles.push(handle);
  }

  // bind to all https addresses
  for (local_addr, (expect_proxy_protocol, sni)) in https_bind {
    log::info!("binding in https mode at {local_addr}");
    let tcp = bind(local_addr)
      .with_context(|| format!("error binding in https mode at addr {local_addr}"))?;

    let mut cert_resolver = CertResolver::new();
    if let Some((_, key)) = sni.first() {
      cert_resolver.set_default(key.clone());
    }

    for (server_name, key) in sni {
      cert_resolver.add(server_name, key);
    }

    let crypto_provider = Arc::new(crypto::default_provider());

    let mut server_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
      .with_protocol_versions(&[&TLS12, &TLS13])
      .with_context(|| format!("error building server config for addr {local_addr}"))?
      .with_no_client_auth()
      .with_cert_resolver(Arc::new(cert_resolver));

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    let server_config = Arc::new(server_config);

    let make_service = proxy::service::HttpMakeService::new(config.clone());

    let handle = tokio::spawn({
      let signal = cancel_token.clone().cancelled_owned();
      let mut wait_start = start.subscribe();
      async move {
        if let Ok(()) = wait_start.changed().await {
          log::info!("starting https server at {}", local_addr);
          serve_https(
            local_addr,
            tcp,
            server_config,
            make_service,
            signal,
            http_server_read_timeout,
            http_server_write_timeout,
            http_graceful_shutdown_timeout,
            expect_proxy_protocol,
            http_proxy_protocol_read_timeout,
          )
          .await;
          log::info!("https server at {} stopped", local_addr);
        }
      }
    });

    handles.push(handle);
  }

  // bind to all stream plain addresses
  for (addr, expect_proxy_protocol) in stream_tcp_bind {
    log::info!("binding in stream tcp mode at {addr}");
    let tcp =
      bind(addr).with_context(|| format!("error binding in stream tcp mode at addr {addr}"))?;

    let service = ProxyStreamService::new(config.clone());

    let handle = tokio::spawn({
      let signal = cancel_token.clone().cancelled_owned();
      let mut wait_start = start.subscribe();
      async move {
        if let Ok(()) = wait_start.changed().await {
          log::info!("starting stream tcp server at {}", addr);
          serve_tcp(
            addr,
            tcp,
            expect_proxy_protocol,
            service,
            signal,
            stream_graceful_shutdown_timeout,
            http_proxy_protocol_read_timeout,
          )
          .await;
          log::info!("stream tcp server at {} stopped", addr);
        }
      }
    });

    handles.push(handle);
  }

  // bind to all stream ssl addresses
  for (addr, (cert_chain, key_der, expect_proxy_protocol)) in stream_ssl_bind {
    let crypto_provider = Arc::new(crypto::default_provider());

    let server_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
      .with_protocol_versions(&[&TLS12, &TLS13])
      .with_context(|| format!("error building server config for addr {addr}"))?
      .with_no_client_auth()
      .with_single_cert(cert_chain, key_der)
      .with_context(|| format!("error building server config for addr {addr}"))?;

    let server_config = Arc::new(server_config);

    log::info!("binding in stream ssl mode at {addr}");
    let tcp =
      bind(addr).with_context(|| format!("error binding in stream ssl mode at addr {addr}"))?;

    let service = ProxyStreamService::new(config.clone());

    let task = {
      let signal = cancel_token.clone().cancelled_owned();
      let mut wait_start = start.subscribe();
      async move {
        if let Ok(()) = wait_start.changed().await {
          log::info!("starting stream ssl server at {}", addr);
          serve_ssl(
            addr,
            tcp,
            expect_proxy_protocol,
            server_config,
            service,
            signal,
            stream_graceful_shutdown_timeout,
            stream_proxy_protocol_read_timeout,
          )
          .await;
        }
      }
    };

    let handle = tokio::spawn(async move {
      task.await;
      log::info!("stream ssl server at {} stopped", addr);
    });

    handles.push(handle);
  }

  // start http healthcheck task for each http(s) upstream handle recursively
  for app in &config.http.apps {
    fn start_handle_heath(
      config: &Config,
      app: &HttpApp,
      handle: &HttpHandle,
      cancel_token: &CancellationToken,
    ) -> Result<(), anyhow::Error> {
      match handle {
        HttpHandle::Return { .. } => {}
        HttpHandle::HeapProfile { .. } => {}
        HttpHandle::Stats { .. } => {}
        #[cfg(feature = "serve-static")]
        HttpHandle::Static { .. } => {}
        HttpHandle::Proxy {
          upstream,
          healthcheck: handle_healthcheck,
          ..
        } => {
          for upstream in upstream.iter() {
            let key = Key::from_config(config, app, upstream).with_context(|| {
              format!(
                "error creating healthcheck key from config for {}",
                upstream.base_url
              )
            })?;

            let healthcheck = crate::option!(
              upstream.healthcheck,
              *handle_healthcheck,
              app.healthcheck,
              config.http.healthcheck,
              => DEFAULT_HTTP_HEALTHCHECK
            );

            let interval = *healthcheck.interval;

            tokio::spawn({
              let upstream_health = upstream.state_health.clone();
              let cancelled = cancel_token.clone().cancelled_owned();
              async move {
                tokio::select! {
                  _ = cancelled => log::info!("received shutdown signal, stopping upstream healthcheck task for {key}"),
                  never = upstream_healthcheck_task(interval, key.clone(), upstream_health) => match never {}
                }
              }
            });
          }
        }

        HttpHandle::When(matchers) => {
          for matcher in matchers {
            start_handle_heath(config, app, &matcher.handle, cancel_token)?;
          }
        }
      }

      Ok(())
    }

    start_handle_heath(&config, app, &app.handle, &cancel_token)?;
  }

  for app in &config.stream.apps {
    match &app.handle {
      StreamHandle::Proxy {
        healthcheck: handle_healthcheck,
        proxy_protocol_write_timeout: handle_proxy_protocol_write_timeout,
        proxy_read_timeout: handle_proxy_read_timeout,
        proxy_write_timeout: handle_proxy_write_timeout,
        proxy_tcp_nodelay: handle_proxy_tcp_nodelay,
        upstream,
        state_round_robin_index: _,
        ketama: _,
        retries: _,
        retry_backoff: _,
        balance: _,
      } => {
        for upstream in upstream {
          let healthcheck = crate::option!(
            upstream.healthcheck,
            *handle_healthcheck,
            app.healthcheck,
            config.stream.healthcheck,
          );

          let interval = match healthcheck {
            Some(healthcheck) => healthcheck.interval.into(),
            None => continue,
          };

          let proxy_tcp_nodelay = crate::option!(
            upstream.proxy_tcp_nodelay,
            *handle_proxy_tcp_nodelay,
            app.proxy_tcp_nodelay,
            config.stream.proxy_tcp_nodelay,
            config.proxy_tcp_nodelay,
            => DEFAULT_PROXY_TCP_NODELAY
          );

          let proxy_protocol_write_timeout = crate::option!(
            @duration
            upstream.proxy_protocol_write_timeout,
            *handle_proxy_protocol_write_timeout,
            config.stream.proxy_protocol_write_timeout,
            config.proxy_protocol_write_timeout,
            => DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT
          );

          let proxy_read_timeout = crate::option!(
            @duration
            upstream.proxy_read_timeout,
            *handle_proxy_read_timeout,
            app.proxy_read_timeout,
            config.stream.proxy_read_timeout,
            => DEFAULT_STREAM_PROXY_READ_TIMEOUT
          );

          let proxy_write_timeout = crate::option!(
            @duration
            upstream.proxy_write_timeout,
            *handle_proxy_write_timeout,
            app.proxy_write_timeout,
            config.stream.proxy_write_timeout,
            => DEFAULT_STREAM_PROXY_WRITE_TIMEOUT
          );

          let upstream_health = upstream.state_health.clone();
          let cancelled = cancel_token.clone().cancelled_owned();

          let sni = upstream.sni.clone();
          let send_proxy_protocol = upstream.send_proxy_protocol;
          let danger_accept_invalid_certs = upstream.danger_accept_invalid_certs;

          let url = upstream.origin.clone();

          tokio::spawn({
            async move {
              tokio::select! {
                _ = cancelled => log::info!("received shutdown signal, stopping stream upstream healthcheck task for {url}"),
                never = stream_upstream_healthcheck_task(
                  interval,
                  upstream_health,
                  url.clone(),
                  proxy_tcp_nodelay,
                  proxy_read_timeout,
                  proxy_write_timeout,
                  send_proxy_protocol,
                  proxy_protocol_write_timeout,
                  sni,
                  danger_accept_invalid_certs,
                ) => match never {}
              }
            }
          });
        }
      }
    }
  }

  // here all addresses are binded
  // let prev_pid = match std::fs::read_to_string(&config.pidfile) {
  //   Ok(prev_pid) => Some(prev_pid),
  //   Err(e) => {
  //     match e.kind() {
  //       std::io::ErrorKind::NotFound => None,
  //       _ => return Err(e.into())
  //     }
  //   }
  // };

  // if let Some(prev_pid) = prev_pid {
  //   log::info!(
  //     "previous pid {} found at {} - sending signal and replacing",
  //     prev_pid,
  //     config.pidfile
  //   );

  //   let prev_pid = prev_pid.parse::<i32>()?;
  //   match nix::sys::signal::kill(nix::unistd::Pid::from_raw(prev_pid), nix::sys::signal::SIGINT) {
  //     Ok(_) => log::info!("sent SIGINT to previous process {prev_pid}"),
  //     Err(e) => log::warn!("failed to send SIGINT to previous process {prev_pid}: {e}"),
  //   };
  // }

  // let pid = std::process::id().to_string();
  // tokio::fs::write(&config.pidfile, pid).await?;

  #[cfg(feature = "log-state")]
  {
    fn log_open_connections(state: &crate::config::Config) {
      for app in &state.http.apps {
        fn log_handle(app: &HttpApp, handle: &HttpHandle) {
          match handle {
            HttpHandle::Return { .. } => {}
            HttpHandle::HeapProfile { .. } => {}
            #[cfg(feature = "serve-static")]
            HttpHandle::Static { .. } => {}
            HttpHandle::Stats { .. } => {}
            HttpHandle::Proxy {
              upstream,
              balance: _,
              ketama: _,
              retries: _,
              retry_backoff: _,
              proxy_headers: _,
              response_headers: _,
              proxy_protocol_write_timeout: _,
              proxy_read_timeout: _,
              proxy_write_timeout: _,
              proxy_tcp_nodelay: _,
              healthcheck: _,
              state_round_robin_index: _,
            } => {
              for up in upstream {
                use itertools::Itertools;
                let server_names = match app.server_names.as_ref() {
                  None => String::from("<all>"),
                  Some(server_names) => server_names.iter().join(", "),
                };

                log::info!(
                  "{} - {} - {} connections",
                  up.base_url,
                  server_names,
                  up.state_open_connections.load(Ordering::Relaxed)
                );
              }
            }
            HttpHandle::When(matchers) => {
              for matcher in matchers {
                log_handle(app, &matcher.handle);
              }
            }
          }
        }

        log_handle(app, &app.handle)
      }

      for app in &state.stream.apps {
        match &app.handle {
          crate::config::StreamHandle::Proxy {
            upstream,
            healthcheck: _,
            balance: _,
            ketama: _,
            retries: _,
            retry_backoff: _,
            proxy_protocol_write_timeout: _,
            proxy_read_timeout: _,
            proxy_write_timeout: _,
            proxy_tcp_nodelay: _,
            state_round_robin_index: _,
          } => {
            for up in upstream {
              log::info!(
                "{} - {} connections",
                up.origin,
                up.state_open_connections.load(Ordering::Relaxed)
              );
            }
          }
        }
      }
    }

    use std::sync::atomic::Ordering;
    let state = config.clone();

    tokio::spawn({
      let cancel = cancel_token.clone().cancelled_owned();
      async move {
        let task = async move {
          loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            log::info!("======================================================");
            log_open_connections(&state);

            log::info!("======================================================");
            crate::serve::log_ip_connections();

            log::info!("======================================================");
            crate::client::pool::log();
          }
        };

        tokio::select! {
          _ = cancel => {}
          _ = task => {}
        }
      }
    })
  };

  // write this process id to the pidfile
  if let Some(pidfile) = &config.pidfile {
    tokio::fs::write(pidfile, std::process::id().to_string())
      .await
      .with_context(|| format!("error writing pidfile to {}", pidfile))?;
  };

  /*
   * If the process reach this point without returning early with an error, it means
   * that the config is valid and the addresses were available for binding by this process
   */

  // signal the serve tasks to start serving requests
  start.send(()).unwrap();

  // this funtion returns a tokio JoinHandler that resolves when all the handles have finished ok
  // or when any spawned serve task panics
  let handle = tokio::spawn(async move {
    futures::future::try_join_all(handles)
      .await
      .context("a serve task panicked")?;

    Ok::<(), anyhow::Error>(())
  });

  Ok(handle)
}
