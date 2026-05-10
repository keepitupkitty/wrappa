use {
  anyhow::Context,
  serde::{Deserialize, Serialize},
  std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream
  },
  tokio::io::AsyncWriteExt
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WrappaRequest {
  pub child: super::Pid,
  pub requested_gid: super::Gid,
  pub requested_uid: super::Uid,
  pub requested_capabilities: String,
  pub needs_setgroups: bool
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status")]
pub enum WrappaResponse {
  Ok,
  Err { message: String }
}

pub async fn send_answer(
  writer: &mut tokio::net::unix::OwnedWriteHalf,
  resp: WrappaResponse
) -> anyhow::Result<()> {
  let mut json = serde_json::to_string(&resp).context("serialise response")?;
  json.push('\n');
  writer.write_all(json.as_bytes()).await.context("send response")?;
  Ok(())
}

pub fn send_request(
  server: &mut UnixStream,
  request: &WrappaRequest
) -> anyhow::Result<()> {
  let mut json =
    serde_json::to_string(&request).context("serialise request")?;
  json.push('\n');
  server.write_all(json.as_bytes()).context("send request")?;
  Ok(())
}

pub fn receive_request_result(
  server: &mut UnixStream
) -> anyhow::Result<WrappaResponse> {
  let mut reader = BufReader::new(server);
  let mut line = String::new();
  reader.read_line(&mut line).context("receive response")?;
  let resp: WrappaResponse =
    serde_json::from_str(line.trim()).context("parse response")?;
  Ok(resp)
}
