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

use anyhow::anyhow;

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
  let version_str = std::fs::read_to_string("/proc/version")
    .map_err(|e| anyhow!("read /proc/version: {}", e))?;

  let kernel_version = version_str
    .split_whitespace()
    .nth(2)
    .ok_or_else(|| anyhow!("malformed /proc/version: {:?}", version_str))?;

  let mut parts = kernel_version.splitn(3, '.');
  let major: u32 =
    parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| {
      anyhow!("cannot parse kernel major from {:?}", kernel_version)
    })?;
  let minor: u32 = parts
    .next()
    .and_then(|s| {
      s.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
    })
    .ok_or_else(|| {
      anyhow!("cannot parse kernel minor from {:?}", kernel_version)
    })?;

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
