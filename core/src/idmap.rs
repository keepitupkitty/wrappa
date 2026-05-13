use {anyhow::Context, std::fs};

fn proc_path(
  pid: super::Pid,
  file: &str
) -> String {
  format!("/proc/{}/{}", pid, file)
}

fn write_proc(
  pid: super::Pid,
  file: &str,
  content: &str
) -> anyhow::Result<()> {
  let path = proc_path(pid, file);
  fs::write(&path, content).with_context(|| format!("write {}", path))
}

fn verify_map_written(
  pid: super::Pid,
  file: &str,
  expected: &str
) -> anyhow::Result<()> {
  let path = proc_path(pid, file);
  let actual =
    fs::read_to_string(&path).with_context(|| format!("readback {}", path))?;

  let parse_map = |s: &str| -> Option<(u64, u64, u64)> {
    let mut parts = s.split_whitespace();
    let a = parts.next()?.parse().ok()?;
    let b = parts.next()?.parse().ok()?;
    let c = parts.next()?.parse().ok()?;
    Some((a, b, c))
  };

  let expected_parsed = parse_map(expected).ok_or_else(|| {
    anyhow::anyhow!("could not parse expected {} content: {:?}", file, expected)
  })?;
  let actual_parsed = parse_map(&actual).ok_or_else(|| {
    anyhow::anyhow!(
      "could not parse readback {} content: {:?} (expected {:?})",
      file,
      actual,
      expected
    )
  })?;

  if expected_parsed != actual_parsed {
    return Err(anyhow::anyhow!(
      "{} readback mismatch: wrote {:?}, read back {:?}",
      path,
      expected.trim(),
      actual.trim()
    ));
  }

  Ok(())
}

pub fn write_idmaps(
  child: super::Pid,
  uid: super::Uid,
  gid: super::Gid,
  supplementary_gids: &[super::Gid],
  needs_setgroups: bool
) -> anyhow::Result<()> {
  let setgroups_val = if needs_setgroups { "allow" } else { "deny" };
  write_proc(child, "setgroups", setgroups_val).context("setgroups")?;

  let uid_map = format!("0 0 1\n{uid} {uid} 1\n");
  write_proc(child, "uid_map", &uid_map).context("uid_map")?;

  verify_map_written(child, "uid_map", &uid_map)
    .context("uid_map readback verification")?;

  let mut seen = std::collections::HashSet::new();
  let mut gid_map = format!("0 0 1\n{gid} {gid} 1\n");
  for &sgid in supplementary_gids {
    if sgid == gid || !seen.insert(sgid) {
      continue;
    }
    gid_map.push_str(&format!("{sgid} {sgid} 1\n"));
  }
  write_proc(child, "gid_map", &gid_map).context("gid_map")?;

  verify_map_written(child, "gid_map", &gid_map)
    .context("gid_map readback verification")?;

  Ok(())
}
