/*
 * Copyright (C) 2026 rsec GNU/Linux
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use {
  anyhow::{Context, anyhow},
  nix::unistd::{chown, getresgid, getresuid},
  std::{
    fs,
    os::{
      raw::{c_int, c_uint},
      unix::fs::PermissionsExt
    },
    path::Path
  },
  tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{UnixListener, UnixStream}
  },
  wrappa_core::{
    WRAPPA_SOCKET,
    auth,
    connection::{self, WrappaRequest, WrappaResponse},
    idmap
  }
};

unsafe extern "C" {
  fn pidfd_open(
    pid: libc::pid_t,
    flags: c_uint
  ) -> c_int;
}

fn is_uid_superuser() -> anyhow::Result<bool> {
  let result = getresuid().context("getresuid")?;
  Ok(
    result.real == 0.into() &&
      result.effective == 0.into() &&
      result.saved == 0.into()
  )
}

fn is_gid_superuser() -> anyhow::Result<bool> {
  let result = getresgid().context("getresgid")?;
  Ok(
    result.real == 0.into() &&
      result.effective == 0.into() &&
      result.saved == 0.into()
  )
}

fn chown_socket(path: &Path) -> anyhow::Result<()> {
  let adm_gid = auth::administrator_gid("wheel")?;
  if let Err(e) = chown(path, Some(0.into()), Some(adm_gid.into())) {
    return Err(anyhow!(
      "Cannot change ownhership of \"{WRAPPA_SOCKET}\": {e}"
    ));
  }
  Ok(())
}

async fn handle_client(stream: UnixStream) -> anyhow::Result<()> {
  let cred = stream.peer_cred().context("SO_PEERCRED")?;

  let peer_uid = cred.uid();
  let peer_gid = cred.gid();
  let peer_pid = cred.pid().ok_or_else(|| anyhow!("peer pid unavailable"))?;

  println!(
    "connection from pid={} uid={} gid={}",
    peer_pid, peer_uid, peer_gid
  );

  let (read_half, mut write_half) = stream.into_split();

  let mut reader = BufReader::new(read_half);

  let mut line = String::new();
  reader.read_line(&mut line).await.context("read request")?;

  let req: WrappaRequest =
    serde_json::from_str(line.trim()).context("parse request")?;

  println!(
    "request: child={} uid={} gid={} caps={:?} setgroups={}",
    req.child,
    req.requested_uid,
    req.requested_gid,
    req.requested_capabilities,
    req.needs_setgroups,
  );

  let child_pidfd: wrappa_core::Pid = unsafe { pidfd_open(req.child, 0) };
  if child_pidfd == -1 {
    return Err(anyhow!(
      "Cannot obtain pidfd for {}: {}",
      req.child,
      std::io::Error::last_os_error()
    ));
  }
  let peer_pidfd: wrappa_core::Pid = unsafe { pidfd_open(peer_pid, 0) };
  if peer_pidfd == -1 {
    return Err(anyhow!(
      "Cannot obtain pidfd for {}: {}",
      peer_pid,
      std::io::Error::last_os_error()
    ));
  }

  if let Err(e) = auth::validate_child_ownership(
    child_pidfd,
    req.child,
    peer_pidfd,
    peer_pid,
    peer_uid,
    peer_gid,
    req.requested_uid,
    req.requested_gid
  ) {
    eprintln!("child ownership check failed: {}", e);
    connection::send_answer(
      &mut write_half,
      WrappaResponse::Err { message: e.to_string() }
    )
    .await?;
    return Ok(());
  }

  let peer_groups = auth::read_peer_groups(peer_pid)
    .context("This user does not have any groups")?;

  if let Err(e) = auth::check_policy(peer_uid, &peer_groups, &req) {
    eprintln!("denied uid={}: {}", peer_uid, e);
    connection::send_answer(
      &mut write_half,
      WrappaResponse::Err { message: e.to_string() }
    )
    .await?;
    return Ok(());
  }

  if let Err(e) = auth::parse_caps(&req.requested_capabilities) {
    connection::send_answer(
      &mut write_half,
      WrappaResponse::Err { message: format!("bad capabilities: {}", e) }
    )
    .await?;
    return Ok(());
  }

  if let Err(e) = auth::verify_in_userns(req.child) {
    connection::send_answer(
      &mut write_half,
      WrappaResponse::Err { message: e.to_string() }
    )
    .await?;
    return Ok(());
  }

  if let Err(e) = auth::verify_not_mapped(req.child) {
    eprintln!("remap attempt for child={}: {}", req.child, e);
    connection::send_answer(
      &mut write_half,
      WrappaResponse::Err { message: e.to_string() }
    )
    .await?;
    return Ok(());
  }

  let child = req.child;
  let req_uid = req.requested_uid;
  let req_gid = req.requested_gid;
  let setgroups = req.needs_setgroups;

  tokio::task::spawn_blocking(move || {
    idmap::write_idmaps(child, req_uid, req_gid, &peer_groups, setgroups)
  })
  .await
  .context("spawn_blocking idmaps")??;

  println!(
    "wrote idmaps for child={}: uid={}->0 gid={}->0 setgroups={}",
    req.child,
    req.requested_uid,
    req.requested_gid,
    if req.needs_setgroups { "allow" } else { "deny" },
  );

  connection::send_answer(&mut write_half, WrappaResponse::Ok).await?;

  Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let path = Path::new(WRAPPA_SOCKET);

  wrappa_core::require_kernel_version()?;

  let is_root_uid = is_uid_superuser()?;
  let is_root_gid = is_gid_superuser()?;

  if !(is_root_gid && is_root_uid) {
    return Err(anyhow!("wrappad must run as root"));
  }

  if path.exists() {
    if let Err(e) = fs::remove_file(path) {
      return Err(anyhow!("Cannot unlink the socket: {e}"));
    }
  }

  let listener = UnixListener::bind(path).context("bind")?;

  fs::set_permissions(path, fs::Permissions::from_mode(0o660))
    .context("chmod socket")?;

  if let Err(e) = chown_socket(path) {
    return Err(anyhow!("{e}"));
  }

  loop {
    match listener.accept().await {
      | Ok((stream, _)) => {
        tokio::spawn(async move {
          if let Err(e) = handle_client(stream).await {
            return Err(anyhow!("handler error: {:#}", e));
          }
          Ok(())
        });
      },
      | Err(e) => return Err(anyhow!("{e}"))
    }
  }
}
