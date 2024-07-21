/// This module allows us to override the process title as shown in programs like top/htop
/// This is directly ported from smaugx/setproctitle. See https://github.com/smaugx/setproctitle
/// Is a known way to set the process title on linux-gnu. The same approach is used by NginX and Google Chrome.
/// On non linux-gnu systems it will fallback to Rust proctitle - https://crates.io/crates/proctitle
/// smaugx/setproctitle: https://github.com/smaugx/setproctitle/blob/main/setproctitle.cc
/// NginX: https://github.com/nginx/nginx/blob/e734df6664e70f118ca3140bcef6d4f1750fa8fa/src/os/unix/ngx_setproctitle.c

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod gnu {
  use parking_lot::Mutex;

  unsafe fn strlen(ptr: *const u8) -> usize {
    let mut len: usize = 0;
    loop {
      let char = *ptr.add(len);
      if char == 0 {
        return len;
      }
      len += 1;
    }
  }

  static LOCK: Mutex<()> = Mutex::new(());

  static mut INITED: bool = false;

  static mut ARGC: usize = 0;
  static mut ARGV: *mut *mut u8 = std::ptr::null_mut();
  static mut ENVP: *mut *mut u8 = std::ptr::null_mut();

  static mut ENVP_SIZE: usize = 0;
  static mut ARGV_SIZE: usize = 0;

  static mut MAX_TITLE_SIZE: usize = 0;

  static mut MOVED_ENV_BUFFER: Option<Vec<u8>> = None;

  static mut ORIGINAL_CMDLINE: Option<String> = None;

  #[used]
  #[link_section = ".init_array"]
  static ARGV_INIT_ARRAY: extern "C" fn(std::ffi::c_int, *mut *mut u8, *mut *mut u8) = {
    extern "C" fn init_wrapper(argc: std::ffi::c_int, argv: *mut *mut u8, envp: *mut *mut u8) {
      unsafe {
        ARGC = argc as usize;
        ARGV = argv;
        ENVP = envp;
      }
    }

    init_wrapper
  };

  pub fn set_proctitle(title: &str) {
    log::debug!("setting proctitle to {}", title);

    let lock = LOCK.lock();

    unsafe {
      // this is safe and will not race because we are holding the lock
      if !INITED {
        INITED = true;

        // get the total size of argv data
        let mut argv_size: usize = 0;
        for i in 0..ARGC {
          let arg = ARGV.add(i);
          if (*arg).is_null() {
            break;
          }
          argv_size += strlen(*arg) + 1;
        }

        ARGV_SIZE = argv_size;

        // get the total size of envp data
        let mut envp_size: usize = 0;
        for i in 0.. {
          let item = ENVP.add(i);
          if (*item).is_null() {
            break;
          }
          envp_size += strlen(*item) + 1;
        }

        ENVP_SIZE = envp_size;

        // copy the env data to a new location and save the location in static memory
        // point the envp pointers to the new location
        let new_env: Vec<u8> = vec![0; envp_size];
        MOVED_ENV_BUFFER = Some(new_env);

        let moved_env_ptr = MOVED_ENV_BUFFER.as_mut().unwrap().as_mut_ptr();

        let mut offset = 0;
        for i in 0.. {
          let item = ENVP.add(i);
          if (*item).is_null() {
            break;
          }

          let size = strlen(*item) + 1;
          let target = moved_env_ptr.add(offset);
          std::ptr::copy_nonoverlapping(*item, target, size);

          *item = target;

          offset += size;
        }

        // set the max title size that can be set, this is the sum of the argv size and envp size
        MAX_TITLE_SIZE = ARGV_SIZE + ENVP_SIZE - 1;

        // copy the original cmdline
        let mut cmdline = Vec::<u8>::new();

        for i in 0..ARGC {
          let arg = ARGV.add(i);
          if arg.is_null() {
            break;
          }
          if i != 0 {
            cmdline.push(b' ');
          }

          for j in 0.. {
            let char = *(*arg).add(j);
            if char == 0 {
              break;
            }
            cmdline.push(char);
          }
        }

        ORIGINAL_CMDLINE = Some(String::from_utf8_lossy(&cmdline).to_string());

        std::ptr::write_bytes(*ARGV, 0, ARGV_SIZE + ENVP_SIZE);

        ARGV.add(1).write(std::ptr::null_mut());
      }

      // the above only happenes once, the following happens every time set_proctitle is called
      let full_title = {
        let mut title: Vec<u8> = title.into();
        // format!("{} | ({})", title, ORIGINAL_CMDLINE.as_ref().unwrap(),).into();

        title.resize(MAX_TITLE_SIZE, 0);

        title.push(0);

        title.shrink_to_fit();

        title
      };

      std::ptr::copy_nonoverlapping(full_title.as_ptr(), *ARGV, full_title.len());
    }

    drop(lock)
  }
}

// this must be called after reading the arguments from the environment
// otherwise cmdline args will be overwritten by the proctitle
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub mod not_gnu {
  use parking_lot::Mutex;

  // we ensure that proctitle is set once at a time
  static LOCK: Mutex<()> = Mutex::new(());

  pub fn set_proctitle(title: &str) {
    log::debug!("setting proctitle to {}", title);

    let lock = LOCK.lock();
    proctitle::set_title(title);
    drop(lock);
  }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub use gnu::set_proctitle;

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub use not_gnu::set_proctitle;

#[cfg(test)]
mod test {

  #[cfg(all(target_os = "linux", target_env = "gnu"))]
  mod gnu {
    use super::super::*;
    use parking_lot::Mutex;

    // if we dont lock the tests they will interfere with each other
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn correctly_set_process_title() {
      let _guard = TEST_LOCK.lock();

      let titles = ["hello world", "goodbye mars", "lets get swifty", "asd"];

      for title in titles {
        set_proctitle(title);

        let cmdline = std::fs::read_to_string("/proc/self/cmdline").unwrap();
        let cmdline = cmdline.trim_end_matches('\0');

        assert_eq!(std::env::args().collect::<String>(), title);
        assert_eq!(cmdline, title);
      }
    }

    #[test]
    fn works_with_really_large_title() {
      let _guard = TEST_LOCK.lock();

      let title = r#"Lorem Ipsum es simplemente el texto de relleno de las imprentas y archivos de texto. Lorem Ipsum ha sido el texto de relleno estándar de las industrias desde el año 1500, cuando un impresor (N. del T. persona que se dedica a la imprenta) desconocido usó una galería de textos y los mezcló de tal manera que logró hacer un libro de textos especimen. No sólo sobrevivió 500 años, sino que tambien ingresó como texto de relleno en documentos electrónicos, quedando esencialmente igual al original. Fue popularizado en los 60s con la creación de las hojas "Letraset", las cuales contenian pasajes de Lorem Ipsum, y más recientemente con software de autoedición, como por ejemplo Aldus PageMaker, el cual incluye versiones de Lorem Ipsum.
        ¿Por qué lo usamos?
        Es un hecho establecido hace demasiado tiempo que un lector se distraerá con el contenido del texto de un sitio mientras que mira su diseño. El punto de usar Lorem Ipsum es que tiene una distribución más o menos normal de las letras, al contrario de usar textos como por ejemplo Contenido aquí, contenido aquí. Estos textos hacen parecerlo un español que se puede leer. Muchos paquetes de autoedición y editores de páginas web usan el Lorem Ipsum como su texto por defecto, y al hacer una búsqueda de 'Lorem Ipsum' va a dar por resultado muchos sitios web que usan este texto si se encuentran en estado de desarrollo. Muchas versiones han evolucionado a través de los años, algunas veces por accidente, otras veces a propósito (por ejemplo insertándole humor y cosas por el estilo).
        ¿De dónde viene?
        Al contrario del pensamiento popular, el texto de Lorem Ipsum no es simplemente texto aleatorio. Tiene sus raices en una pieza clasica de la literatura del Latin, que data del año 45 antes de Cristo, haciendo que este adquiera mas de 2000 años de antiguedad. Richard McClintock, un profesor de Latin de la Universidad de Hampden-Sydney en Virginia, encontró una de las palabras más oscuras de la lengua del latín, 'consecteur', en un pasaje de Lorem Ipsum, y al seguir leyendo distintos textos del latín, descubrió la fuente indudable. Lorem Ipsum viene de las secciones 1.10.32 y 1.10.33 de 'de Finnibus Bonorum et Malorum' (Los Extremos del Bien y El Mal) por Cicero, escrito en el año 45 antes de Cristo. Este libro es un tratado de teoría de éticas, muy popular durante el Renacimiento. La primera linea del Lorem Ipsum, 'Lorem ipsum dolor sit amet..', viene de una linea en la sección 1.10.32
        El trozo de texto estándar de Lorem Ipsum usado desde el año 1500 es reproducido debajo para aquellos interesados. Las secciones 1.10.32 y 1.10.33 de de Finibus Bonorum et Malorum por Cicero son también reproducidas en su forma original exacta, acompañadas por versiones en Inglés de la traducción realizada en 1914 por H. Rackham.
        ¿Dónde puedo conseguirlo?
        Hay muchas variaciones de los pasajes de Lorem Ipsum disponibles, pero la mayoría sufrió alteraciones en alguna manera, ya sea porque se le agregó humor, o palabras aleatorias que no parecen ni un poco creíbles. Si vas a utilizar un pasaje de Lorem Ipsum, necesitás estar seguro de que no hay nada avergonzante escondido en el medio del texto. Todos los generadores de Lorem Ipsum que se encuentran en Internet tienden a repetir trozos predefinidos cuando sea necesario, haciendo a este el único generador verdadero (válido) en la Internet. Usa un diccionario de mas de 200 palabras provenientes del latín, combinadas con estructuras muy útiles de sentencias, para generar texto de Lorem Ipsum que parezca razonable. Este Lorem Ipsum generado siempre estará libre de repeticiones, humor agregado o palabras no características del lenguaje, etc.
        5 párrafos
	      5 palabras
	      5 bytes
	      5 listas"#;

      set_proctitle(title);

      let cmdline = std::fs::read_to_string("/proc/self/cmdline").unwrap();
      let cmdline = cmdline.trim_end_matches('\0');

      let arg = std::env::args().next().unwrap();
      eprintln!("{}", arg);

      assert!(!arg.is_empty());
      assert!(!cmdline.is_empty());

      assert!(title.starts_with(&arg));
      assert!(title.starts_with(cmdline));
    }

    // TODO: double check this test
    #[test]
    fn doesnt_modify_env_vars() {
      let _guard = TEST_LOCK.lock();

      let title = r#"Lorem Ipsum es simplemente el texto de relleno de las imprentas y archivos de texto. Lorem Ipsum ha sido el texto de relleno estándar de las industrias desde el año 1500, cuando un impresor (N. del T. persona que se dedica a la imprenta) desconocido usó una galería de textos y los mezcló de tal manera que logró hacer un libro de textos especimen. No sólo sobrevivió 500 años, sino que tambien ingresó como texto de relleno en documentos electrónicos, quedando esencialmente igual al original. Fue popularizado en los 60s con la creación de las hojas "Letraset", las cuales contenian pasajes de Lorem Ipsum, y más recientemente con software de autoedición, como por ejemplo Aldus PageMaker, el cual incluye versiones de Lorem Ipsum.
        ¿Por qué lo usamos?
        Es un hecho establecido hace demasiado tiempo que un lector se distraerá con el contenido del texto de un sitio mientras que mira su diseño. El punto de usar Lorem Ipsum es que tiene una distribución más o menos normal de las letras, al contrario de usar textos como por ejemplo Contenido aquí, contenido aquí. Estos textos hacen parecerlo un español que se puede leer. Muchos paquetes de autoedición y editores de páginas web usan el Lorem Ipsum como su texto por defecto, y al hacer una búsqueda de 'Lorem Ipsum' va a dar por resultado muchos sitios web que usan este texto si se encuentran en estado de desarrollo. Muchas versiones han evolucionado a través de los años, algunas veces por accidente, otras veces a propósito (por ejemplo insertándole humor y cosas por el estilo).
        ¿De dónde viene?
        Al contrario del pensamiento popular, el texto de Lorem Ipsum no es simplemente texto aleatorio. Tiene sus raices en una pieza clasica de la literatura del Latin, que data del año 45 antes de Cristo, haciendo que este adquiera mas de 2000 años de antiguedad. Richard McClintock, un profesor de Latin de la Universidad de Hampden-Sydney en Virginia, encontró una de las palabras más oscuras de la lengua del latín, 'consecteur', en un pasaje de Lorem Ipsum, y al seguir leyendo distintos textos del latín, descubrió la fuente indudable. Lorem Ipsum viene de las secciones 1.10.32 y 1.10.33 de 'de Finnibus Bonorum et Malorum' (Los Extremos del Bien y El Mal) por Cicero, escrito en el año 45 antes de Cristo. Este libro es un tratado de teoría de éticas, muy popular durante el Renacimiento. La primera linea del Lorem Ipsum, 'Lorem ipsum dolor sit amet..', viene de una linea en la sección 1.10.32
        El trozo de texto estándar de Lorem Ipsum usado desde el año 1500 es reproducido debajo para aquellos interesados. Las secciones 1.10.32 y 1.10.33 de de Finibus Bonorum et Malorum por Cicero son también reproducidas en su forma original exacta, acompañadas por versiones en Inglés de la traducción realizada en 1914 por H. Rackham.
        ¿Dónde puedo conseguirlo?
        Hay muchas variaciones de los pasajes de Lorem Ipsum disponibles, pero la mayoría sufrió alteraciones en alguna manera, ya sea porque se le agregó humor, o palabras aleatorias que no parecen ni un poco creíbles. Si vas a utilizar un pasaje de Lorem Ipsum, necesitás estar seguro de que no hay nada avergonzante escondido en el medio del texto. Todos los generadores de Lorem Ipsum que se encuentran en Internet tienden a repetir trozos predefinidos cuando sea necesario, haciendo a este el único generador verdadero (válido) en la Internet. Usa un diccionario de mas de 200 palabras provenientes del latín, combinadas con estructuras muy útiles de sentencias, para generar texto de Lorem Ipsum que parezca razonable. Este Lorem Ipsum generado siempre estará libre de repeticiones, humor agregado o palabras no características del lenguaje, etc.
        5 párrafos
        5 palabras
        5 bytes
        5 listas"#;

      let args = std::env::vars().collect::<Vec<(String, String)>>();

      set_proctitle(title);

      let args_after = std::env::vars().collect::<Vec<(String, String)>>();

      assert_eq!(args, args_after);
    }
  }
}
