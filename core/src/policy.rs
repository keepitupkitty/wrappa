use {
  crate::{Gid, Uid},
  anyhow::anyhow,
  caps::Capability,
  nix::unistd::{Group, User}
};

// TODO: Handle those when we will have config file support
pub const ALLOWED_USERS: &[&str] = &["root", "veronica"];
pub const ALLOWED_GROUPS: &[&str] = &["wheel", "sudo"];

pub fn allowed_uids() -> Vec<Uid> {
  ALLOWED_USERS
    .iter()
    .filter_map(|name| {
      User::from_name(name).ok().flatten().map(|u| u.uid.as_raw())
    })
    .collect()
}

pub fn allowed_gids() -> Vec<Gid> {
  ALLOWED_GROUPS
    .iter()
    .filter_map(|name| {
      Group::from_name(name).ok().flatten().map(|g| g.gid.as_raw())
    })
    .collect()
}

pub fn is_admitted(
  peer_uid: Uid,
  peer_groups: &[Gid]
) -> anyhow::Result<()> {
  if peer_uid == 0 {
    return Ok(());
  }

  let uids = allowed_uids();
  if uids.contains(&peer_uid) {
    return Ok(());
  }

  let gids = allowed_gids();
  for peer_gid in peer_groups {
    if gids.contains(peer_gid) {
      return Ok(());
    }
  }

  let user_str = ALLOWED_USERS.join(", ");
  let group_str = ALLOWED_GROUPS.join(", ");
  Err(anyhow!(
    "uid {} is not in the allowed users [{}] or \
     allowed groups [{}]",
    peer_uid,
    user_str,
    group_str
  ))
}

pub fn is_allowed_cap(cap: Capability) -> bool {
  matches!(cap, |Capability::CAP_SYS_ADMIN)
}

pub fn is_allowed_cap_su(cap: Capability) -> bool {
  matches!(cap, |Capability::CAP_SETUID| Capability::CAP_SETGID |
    Capability::CAP_DAC_READ_SEARCH |
    Capability::CAP_DAC_OVERRIDE |
    Capability::CAP_SETPCAP)
}
