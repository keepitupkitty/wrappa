use {
  crate::{Gid, Pid, Uid},
  anyhow::{Context, anyhow},
  caps::{CapSet, Capability},
  nix::unistd::Group,
  std::{
    fs,
    io::{BufRead, BufReader},
    str::FromStr
  }
};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct PidFDInfo {
  request_mask: u64,
  cgroupid: u64,
  pid: u32,
  tgid: u32,
  ppid: u32,
  ruid: u32,
  rgid: u32,
  euid: u32,
  egid: u32,
  suid: u32,
  sgid: u32,
  fsuid: u32,
  fsgid: u32,
  spare0: [u32; 1]
}

nix::ioctl_readwrite!(pidfd_get_info, 0xFF, 11, PidFDInfo);

pub fn validate_child_ownership(
  child_pidfd: Pid,
  child_pid: Pid,
  peer_pidfd: Pid,
  peer_pid: Pid,
  peer_uid: Uid,
  peer_gid: Gid,
  requested_uid: Uid,
  requested_gid: Gid
) -> anyhow::Result<()> {
  let mut info: PidFDInfo = Default::default();
  unsafe {
    pidfd_get_info(child_pidfd, &mut info).with_context(|| {
      format!("Cannot get file descriptor information for pid {}", child_pid)
    })?;
  }

  let mut peer_info: PidFDInfo = Default::default();
  unsafe {
    pidfd_get_info(peer_pidfd, &mut peer_info).with_context(|| {
      format!("Cannot get file descriptor information for pid {}", peer_pid)
    })?;
  }

  if peer_info.euid != peer_uid || peer_info.egid != peer_gid {
    return Err(anyhow!(
      "peer PID {} euid={} egid={} (SO_PEERCRED says euid={} egid={})",
      peer_pid,
      peer_info.euid,
      peer_info.egid,
      peer_uid,
      peer_gid
    ));
  }

  if info.ppid == 0 {
    return Err(anyhow!(
      "child PID {} has ppid=0, which is not a valid userspace parent",
      child_pid
    ));
  }

  if info.ppid != peer_pid as u32 {
    return Err(anyhow!(
      "child PID {} parent is {} but requester pid is {}",
      child_pid,
      info.ppid,
      peer_pid
    ));
  }

  if info.ruid != peer_uid || info.rgid != peer_gid {
    return Err(anyhow!(
      "child PID {} owned by uid={} gid={} (peer is uid={} gid={})",
      child_pid,
      info.ruid,
      info.rgid,
      peer_uid,
      peer_gid
    ));
  }

  if peer_uid != 0 {
    if requested_uid != peer_uid {
      return Err(anyhow!(
        "uid {} may not request mapping to uid {} (must map own uid)",
        peer_uid,
        requested_uid
      ));
    }
    if requested_gid != peer_gid {
      return Err(anyhow!(
        "gid {} may not request mapping to gid {} (must map own gid)",
        peer_gid,
        requested_gid
      ));
    }
  }

  Ok(())
}

pub fn verify_not_mapped(child: Pid) -> anyhow::Result<()> {
  let uid_map_path = format!("/proc/{}/uid_map", child);
  let content = fs::read_to_string(&uid_map_path)
    .with_context(|| format!("read {}", uid_map_path))?;

  if !content.trim().is_empty() {
    return Err(anyhow!(
      "child pid {} uid_map is already written ({:?}), \
       refusing to re-map",
      child,
      content.trim()
    ));
  }

  let gid_map_path = format!("/proc/{}/gid_map", child);
  let content = fs::read_to_string(&gid_map_path)
    .with_context(|| format!("read {}", gid_map_path))?;

  if !content.trim().is_empty() {
    return Err(anyhow!(
      "child pid {} gid_map is already written ({:?}), \
       refusing to re-map",
      child,
      content.trim()
    ));
  }

  Ok(())
}

pub fn read_peer_groups(peer_pid: Pid) -> anyhow::Result<Vec<Gid>> {
  let fmt = format!("/proc/{peer_pid}/status");

  let file = fs::File::open(fmt).context("Cannot open {fmt}")?;
  let reader = BufReader::new(file);
  let mut buf: Vec<u32> = Vec::new();

  for line in reader.lines() {
    if let Ok(line) = line &&
      line.contains("Groups:")
    {
      let mut split = line.split_whitespace();
      while let Some(s) = split.next() {
        let parsed: u32 = match s.parse() {
          | Ok(ok) => ok,
          | Err(_) => continue
        };
        buf.push(parsed);
      }
    }
  }

  if !buf.is_empty() {
    return Ok(buf);
  }

  Err(anyhow!("No groups for this user"))
}

pub fn verify_in_userns(child: super::Pid) -> anyhow::Result<()> {
  let child_ns = fs::read_link(format!("/proc/{}/ns/user", child))
    .context("readlink child userns")?;
  let init_ns =
    fs::read_link("/proc/1/ns/user").context("readlink init userns")?;

  if child_ns == init_ns {
    return Err(anyhow!(
      "child pid {} is not in a new user namespace \
             (userns matches init: {:?})",
      child,
      child_ns
    ));
  }

  Ok(())
}

pub fn parse_caps(s: &str) -> anyhow::Result<Vec<Capability>> {
  if s.trim().is_empty() {
    return Ok(vec![]);
  }
  s.split(',')
    .map(|name| {
      let name = name.trim().to_uppercase();
      let name =
        if name.starts_with("CAP_") { name } else { format!("CAP_{}", name) };
      Capability::from_str(&name)
        .map_err(|_| anyhow!("unknown capability: {}", name))
    })
    .collect()
}

pub fn administrator_gid(admin_group: &str) -> anyhow::Result<super::Gid> {
  Group::from_name(admin_group)?
    .map(|g| g.gid.as_raw())
    .ok_or_else(|| anyhow!("Administrator group not found"))
}

pub fn check_policy(
  peer_uid: Uid,
  peer_groups: &[Gid],
  request: &super::connection::WrappaRequest
) -> anyhow::Result<()> {
  super::policy::is_admitted(peer_uid, peer_groups)?;

  if peer_uid != 0 {
    let requested = parse_caps(&request.requested_capabilities)?;
    for cap in &requested {
      if !super::policy::is_allowed_cap(*cap) {
        return Err(anyhow!("capability {:?} not permitted by policy", cap));
      }
    }
  }

  Ok(())
}

pub fn set_capabilities(
  request: &super::connection::WrappaRequest
) -> anyhow::Result<()> {
  let wanted = parse_caps(&request.requested_capabilities)?;

  let all_caps = caps::all();

  for cap in &all_caps {
    if !wanted.contains(cap) {
      let _ = caps::drop(None, CapSet::Permitted, *cap);
    }
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

  Ok(())
}
