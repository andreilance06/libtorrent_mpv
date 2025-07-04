local msg = require("mp.msg")
local http = require("socket.http")
local ltn12 = require("ltn12")

local Config = require("lib/config")
local State = require("lib/state")

local Client = {}

local unpack = unpack or table.unpack -- For compatibility with Lua 5.1
local exe
if PLATFORM == "windows" then
  exe = "libtorrent_mpv.exe"
else
  exe = "libtorrent_mpv"
end

function Client.start()
  if State.client_running then
    return true
  end

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    -- capture_stderr = true,
    args = { mp.get_script_directory() .. '/' .. exe, unpack(Config.get_client_args()) },
    detach = true
  })

  if cmd.status ~= 0 then
    msg.error("error starting client:", cmd.stderr)
    return false
  end

  msg.debug("Started torrent server")
  State.client_running = true
  State.launched_by_us = true
  State.find_service()
  return true
end

function Client.close()
  if not State.client_running then
    msg.debug("Client is already closed")
    return true
  end
  -- if not State.launched_by_us then
  --   msg.debug("Can't close client launched by another process")
  --   return false
  -- end

  local url = "http://" .. State.service_ip .. ":" .. State.service_port .. "/shutdown"
  local response_body = {}
  local res, code = http.request {
    url = url,
    sink = ltn12.sink.table(response_body),
    method = "GET"
  }

  if code ~= 200 then
    msg.error("error closing client: http status is", code)
    return false
  end

  State.client_running = false
  -- State.launched_by_us = false
  State.torrents = {}
  msg.debug("Closed torrent server")
  return true
end

function Client.add(torrent_url)
  if not State.client_running then
    msg.error("error adding torrent: server must be online")
    return nil
  end

  local url = "http://" .. State.service_ip .. ":" .. State.service_port .. "/torrents"
  local response_body = {}
  local res, code = http.request {
    url = url,
    sink = ltn12.sink.table(response_body),
    method = "POST",
    source = ltn12.source.string(torrent_url),
    headers = {
      ["content-length"] = tostring(#torrent_url)
    }
  }

  local playlist = table.concat(response_body)
  if code ~= 200 or not playlist or #playlist == 0 then
    msg.debug("Unable to get playlist for", torrent_url)
    return nil
  end

  return playlist
end

function Client.remove(info_hash, delete_files)
  if not State.client_running then
    msg.error("error deleting torrent: server must be online")
    return false
  end

  local exists = false
  for _, v in pairs(State.torrents) do
    if v.InfoHash == info_hash then
      exists = true
      break
    end
  end

  if not exists then
    msg.error("error deleting torrent: torrent", info_hash, "does not exist")
    return false
  end

  if delete_files == nil then
    delete_files = false
  end

  local url = "http://" ..
      State.service_ip ..
      ":" .. State.service_port .. "/torrents/" .. info_hash .. "?DeleteFiles=" .. tostring(delete_files)
  local response_body = {}
  local res, code = http.request {
    url = url,
    sink = ltn12.sink.table(response_body),
    method = "DELETE"
  }

  return code == 200
end

return Client
