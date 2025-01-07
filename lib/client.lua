local msg = require("mp.msg")

local Config = require("lib/config")
local State = require("lib/state")

local Client = {}

function Client.start()
  if State.client_running then
    return true
  end

  if State.is_running() then
    msg.debug("Client is already running")
    State.client_running = true
    return true
  end

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    capture_stderr = true,
    args = { mp.get_script_directory() .. "/libtorrent_mpv.exe", table.unpack(Config.get_client_args()) },
    detach = true
  })

  if cmd.status ~= 0 then
    msg.error("error starting client:", cmd.stderr)
    return false
  end

  msg.debug("Started torrent server")
  State.client_running = true
  -- State.launched_by_us = true
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
  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    capture_stderr = true,
    args = { "curl", "127.0.0.1:" .. Config.opts.port .. "/shutdown" }
  })

  if cmd.status ~= 0 then
    msg.error("error closing client:", cmd.stderr)
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

  local cmd = mp.command_native({
    name = "subprocess",
    capture_stdout = true,
    args = { "curl", "-s", "-f", "--retry", "10", "--retry-delay", "1", "--retry-connrefused", "-d",
      torrent_url, "127.0.0.1:" .. Config.opts.port .. "/torrents" }
  })

  local playlist = cmd.stdout
  if cmd.status ~= 0 or not playlist or #playlist == 0 then
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

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    args = { "curl", "-X", "DELETE", "127.0.0.1:" .. Config.opts.port .. "/torrents/" .. info_hash .. "?DeleteFiles=" .. tostring(delete_files) },
  })

  return cmd.status ~= 0
end

return Client
