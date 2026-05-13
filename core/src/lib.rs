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
  nix::sys::utsname::uname,
  std::{
    borrow::Cow,
    ffi::{CStr, CString}
  }
};

pub mod auth;
pub mod connection;
pub mod idmap;
pub mod policy;

pub type Pid = libc::pid_t;
pub type Uid = libc::uid_t;
pub type Gid = libc::gid_t;

pub const WRAPPA_SOCKET: &'static str = "/run/wrappad.sock";

const REQUIRED_KERNEL_MAJOR: u32 = 6;
const REQUIRED_KERNEL_MINOR: u32 = 13;

pub fn require_kernel_version() -> anyhow::Result<()> {
  let uts = uname().context("Failed to call uname")?;
  let version =
    uts.release().to_str().context("Malformed kerrnel version string")?;
  let kver = version.splitn(2, '.');
  let major: u32 =
    kver.clone().next().context("Cannot get major kernel version")?.parse()?;
  let minor: u32 =
    kver.clone().next().context("Cannot get minor kernel version")?.parse()?;

  if (major, minor) < (REQUIRED_KERNEL_MAJOR, REQUIRED_KERNEL_MINOR) {
    return Err(anyhow!(
      "kernel {}.{} is too old: wrappad requires >= {}.{} \
       (PIDFD_GET_INFO with full credential fields)",
      major,
      minor,
      REQUIRED_KERNEL_MAJOR,
      REQUIRED_KERNEL_MINOR
    ));
  }

  Ok(())
}

#[inline]
pub fn strtocstr(s: &str) -> Cow<'static, CStr> {
  let bytes: Vec<u8> = s.bytes().take_while(|&b| b != 0).collect();

  unsafe { Cow::Owned(CString::from_vec_unchecked(bytes)) }
}
