use {
  anyhow::{Context, anyhow},
  clap::Parser,
  nix::{
    sched::{CloneFlags, clone},
    sys::{
      resource::{Resource, getrlimit},
      signal::{Signal, kill},
      wait::{WaitStatus, waitpid}
    },
    unistd::{getgid, getuid, pipe}
  },
  std::{
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::exit
  },
  wrappa_core::{WRAPPA_SOCKET, connection}
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

    // TODO: mounts, caps and exec
    println!("We are in the child!!!");
    println!("cmds: {:#?}", argv0_args);
    let status = std::process::Command::new("zsh")
      .status()
      .expect("Failed to execute command");
    status.code().unwrap_or(-1) as isize
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
