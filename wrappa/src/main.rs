use {
  anyhow::{Context, anyhow},
  caps::{CapSet, Capability},
  clap::Parser,
  nix::{
    sched::{CloneFlags, clone},
    sys::{
      resource::{Resource, getrlimit},
      signal::{Signal, kill},
      wait::{WaitStatus, waitpid}
    },
    unistd::{execve, getgid, getuid, pipe}
  },
  std::{
    ffi::CStr,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::exit
  },
  wrappa_core::{
    WRAPPA_SOCKET,
    auth,
    connection::{self, WrappaResponse}
  }
};

#[derive(Parser, Debug)]
#[command(name = "wrappa", allow_hyphen_values = true)]
#[command(about = "A client that wraps and isolates setuid programs", long_about = None)]
pub struct Args {
  /// Map desired user ID to the sandbox
  #[arg(short = 'u', long)]
  pub uid: Option<u32>,

  /// Map desired group ID to the sandbox
  #[arg(short = 'g', long)]
  pub gid: Option<u32>,

  /// Specify desired capabilities to use withing the sandbox
  #[arg(short = 'c', long)]
  pub caps: String,

  /// Specify whether you need setgroups to be available in sandbox or not
  #[arg(long, default_value_t = false)]
  pub setgroups: bool,

  /// Command to execute
  #[arg(last = true, required = true)]
  pub command: Vec<String>
}

fn main() -> anyhow::Result<()> {
  let args = Args::parse();

  let mut stream = UnixStream::connect(WRAPPA_SOCKET)
    .context("cannot connect to wrappa socket")?;

  let argv0 = &args.command[0];
  if !argv0.starts_with('/') {
    return Err(anyhow::anyhow!(
      "binary must be an absolute path, got {:?}",
      argv0
    ));
  }

  let argv0_args: &[String] = &args.command[1..];

  let caps = args.caps;
  let setgroups = args.setgroups;
  let gid = args.gid.unwrap_or(getgid().into());
  let uid = args.uid.unwrap_or(getuid().into());

  let (write_fd, read_fd): (OwnedFd, OwnedFd) = match pipe() {
    | Ok(s) => s,
    | Err(e) => return Err(anyhow!("Cannot crate pipe: {e}"))
  };

  let (stack_size, _) = match getrlimit(Resource::RLIMIT_STACK) {
    | Ok(s) => s,
    | Err(e) => return Err(anyhow!("Cannot get stack size limit: {e}"))
  };
  let stack_size: usize =
    if stack_size > usize::MAX as u64 { 8192 } else { stack_size as usize };

  let mut stack: Vec<u8> = vec![0u8; stack_size];

  let child_callback: Box<dyn FnMut() -> isize> = Box::new(|| {
    drop(write_fd.try_clone());

    let mut buf = [0u8; 1];
    let _ = nix::unistd::read(&read_fd, &mut buf);
    drop(read_fd.try_clone());

    // Need filesystem and PID namespace
    // TODO: mount /dev as tmpfs and bind only needed stuff RIGHT HERE
    // mount /bin /lib /libexec /sbin /usr /opt with nosuid and rdonly
    // (shall be checked if such path exists + if /bin /sbin /lib /libexec are
    // links then dont mount case for merged /usr)
    // mount /sys, /tmp as tmpfs
    // mount /proc

    let all_caps = caps::all();
    let wanted: Vec<Capability> = match auth::parse_caps(&caps) {
      | Ok(result) => result,
      | Err(e) => {
        eprintln!("Cannot parse capability: {e}");
        exit(127);
      }
    };

    for cap in &all_caps {
      if !wanted.contains(cap) {
        let _ = caps::drop(None, CapSet::Permitted, *cap);
      }
    }

    let response = match connection::receive_request_result(&mut stream) {
      | Ok(result) => result,
      | Err(e) => {
        eprintln!("Cannot get response: {e}");
        exit(127);
      }
    };

    if response != WrappaResponse::Ok {
      eprintln!("Access denied");
      exit(127);
    }

    for cap in &all_caps {
      if wanted.contains(cap) {
        let _ = caps::raise(None, CapSet::Effective, *cap);
        let _ = caps::raise(None, CapSet::Inheritable, *cap);
      } else {
        let _ = caps::drop(None, CapSet::Effective, *cap);
        let _ = caps::drop(None, CapSet::Inheritable, *cap);
      }
    }

    for cap in &wanted {
      if let Err(e) = caps::raise(None, CapSet::Ambient, *cap) {
        eprintln!("ambient raise {:?} failed: {}", cap, e);
        exit(127);
      }
    }

    if caps::has_cap(None, CapSet::Effective, Capability::CAP_SETPCAP)
      .unwrap_or(false)
    {
      let securebits: libc::c_int = libc::SECBIT_NOROOT |
        libc::SECBIT_NOROOT_LOCKED |
        libc::SECBIT_NO_SETUID_FIXUP |
        libc::SECBIT_NO_SETUID_FIXUP_LOCKED;

      let ret =
        unsafe { libc::prctl(libc::PR_SET_SECUREBITS, securebits, 0, 0, 0) };
      if ret != 0 {
        eprintln!(
          "wrappa: warning: PR_SET_SECUREBITS failed: {}",
          std::io::Error::last_os_error()
        );
        exit(127);
      }
    }

    let path = wrappa_core::strtocstr(&argv0);
    let mut args: Vec<&'static CStr> = Vec::new();
    for a in argv0_args {
      let cstr = wrappa_core::strtocstr(&a).as_ptr();
      unsafe { args.push(CStr::from_ptr(cstr)) };
    }

    let env: &[&'static CStr] = &[
      c"HOME=/tmp",
      c"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
      c"LC_ALL=C.UTF-8",
      c"LC_MESSAGES=ru_RU.UTF-8"
    ];

    match execve(&path, args.as_slice(), env) {
      | Ok(_) => return 0,
      | Err(e) => {
        eprintln!("Cannot run executable \"{argv0}\": {e}");
        exit(127);
      }
    }
  });

  let clone_flags = CloneFlags::CLONE_NEWUSER;

  let child_pid = unsafe {
    clone(
      child_callback,
      stack.as_mut_slice(),
      clone_flags,
      Some(Signal::SIGCHLD as i32)
    )?
  };

  let request = connection::WrappaRequest {
    child: child_pid.as_raw(),
    requested_gid: gid,
    requested_uid: uid,
    requested_capabilities: caps,
    needs_setgroups: setgroups
  };

  drop(read_fd);

  if let Err(e) = connection::send_request(&mut stream, &request) {
    drop(write_fd.try_clone());
    kill(child_pid, Some(Signal::SIGKILL))?;
    return Err(anyhow!("Failed to send request: {e}"));
  }

  drop(write_fd);

  match waitpid(child_pid, None) {
    | Ok(WaitStatus::Exited(_, status)) => {
      exit(status.into());
    },
    | Ok(WaitStatus::Signaled(_, signal, _)) => {
      exit(128 + signal as i32);
    },
    | Err(e) => return Err(anyhow!("waitpid failed: {e}")),
    | _ => return Ok(())
  }
}
