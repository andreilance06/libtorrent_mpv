local msg = require("mp.msg")

local Config = require("lib/config")
local State = require("lib/state")

local Client = {}

local unpack = unpack or table.unpack -- For compatibility with Lua 5.1

function Client.start()
  if State.client_running then
    return true
  end

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    -- capture_stderr = true,
    args = { mp.get_script_directory() .. '/' .. "libtorrent_mpv" .. BINARY_SUFFIX, unpack(Config.get_client_args()) },
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

  if not State.launched_by_us then
    msg.debug("Can't close client not launched by us")
    return false
  end

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    capture_stderr = true,
    args = { "curl", "http://" .. State.service_ip .. ':' .. State.service_port .. "/shutdown" }
  })

  if cmd.status ~= 0 then
    msg.error("error closing client:", cmd.stderr)
    return false
  end

  State.client_running = false
  State.launched_by_us = false
  State.torrents = {}
  msg.debug("Closed torrent server")
  return true
end

function Client.add(torrent_url)
  if not State.client_running then
    msg.error("error adding torrent: server must be online")
    return nil
  end

  local cmd = mp.command_native({
    name = "subprocess",
    capture_stdout = true,
    args = { "curl", "-s", "-f", "-d",
      torrent_url, "http://" .. State.service_ip .. ':' .. State.service_port .. "/torrents" }
  })

  if cmd.status ~= 0 or not cmd.stdout or #cmd.stdout == 0 then
    msg.debug("Unable to get playlist for", torrent_url)
  end

  return cmd.stdout
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

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    args = { "curl", "-X", "DELETE", "http://" .. State.service_ip .. ':' .. State.service_port .. "/torrents/" .. info_hash .. "?DeleteFiles=" .. tostring(delete_files) },
  })

  return cmd.status == 0
end

return Client
