use {
  crate::{Gid, Uid},
  anyhow::anyhow,
  caps::Capability,
  nix::{
    sys::stat::{Mode, stat},
    unistd::{Group, User}
  }
};

// TODO: Handle those when we will have config file support
pub const ALLOWED_USERS: &[&str] = &["root", "veronica"];

const ADMINISTRATOR_GROUP: &str = "wheel";
const ALLOWED_BINARIES: &[&str] = &[
  "/usr/bin/.su.unwrapped",
  "/usr/bin/.sudo.unwrapped",
  "/usr/bin/.doas.unwrapped"
];

pub fn is_binary_allowed(b: &str) -> bool {
  let in_allowed = ALLOWED_BINARIES.contains(&b);
  let Ok(st) = stat(b) else {
    return false;
  };
  let m = Mode::from_bits_retain(st.st_mode);
  let issetugid = m.contains(Mode::S_ISUID) || m.contains(Mode::S_ISGID);
  in_allowed && !issetugid
}

pub fn allowed_uids() -> Vec<Uid> {
  ALLOWED_USERS
    .iter()
    .filter_map(|name| {
      User::from_name(name).ok().flatten().map(|u| u.uid.as_raw())
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

  let wheel_gid = match Group::from_name(ADMINISTRATOR_GROUP) {
    | Ok(Some(g)) => g.gid,
    | _ => {
      return Err(anyhow!(
        "no `{ADMINISTRATOR_GROUP}` group available on your system"
      ));
    }
  };

  let uids = allowed_uids();
  if uids.contains(&peer_uid) && peer_groups.contains(&wheel_gid.as_raw()) {
    return Ok(());
  }

  let user_str = ALLOWED_USERS.join(", ");
  Err(anyhow!(
    "uid {} is not in the allowed users [{}] or \
     allowed groups [{}]",
    peer_uid,
    user_str,
    ADMINISTRATOR_GROUP
  ))
}

pub fn is_allowed_cap(cap: Capability) -> bool {
  matches!(cap, |Capability::CAP_SETUID| Capability::CAP_SETGID |
    Capability::CAP_DAC_READ_SEARCH |
    Capability::CAP_SETPCAP)
}
