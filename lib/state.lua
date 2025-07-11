local msg = require("mp.msg")
local utils = require("mp.utils")
local Config = require("lib/config")


local State = {
  torrents = {},
  client_running = false,
  launched_by_us = false,
  service_ip = nil,
  service_port = nil
}

function State.find_service()
  if State.launched_by_us then
    State.service_ip = "127.0.0.1"
    State.service_port = Config.opts.port
    return
  end

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    capture_stdout = true,
    capture_stderr = true,
    args = { "curl", "-s", "--connect-timeout", "0.1", "http://127.0.0.1:" .. Config.opts.port .. "/torrents" }
  })

  if cmd.status == 0 then
    State.client_running = true
    State.launched_by_us = true
    State.service_ip = "127.0.0.1"
    State.service_port = Config.opts.port
    return
  end

  if Config.opts.SearchLocalNetwork then
    local cmd = mp.command_native({
      name = "subprocess",
      playback_only = false,
      capture_stdout = true,
      capture_stderr = true,
      args = { mp.get_script_directory() .. '/' .. "ltmpv-sd" .. BINARY_SUFFIX, "find" }
    })

    if cmd.status == 0 then
      local stdout = cmd.stdout or ""
      if stdout ~= "" then
        local ip, port = stdout:match("^(%d+%.%d+%.%d+%.%d+):(%d+)$")
        if ip and port then
          State.launched_by_us = false
          State.client_running = true
          State.service_ip     = ip
          State.service_port   = port
          return
        end
      end
    end
  end

  State.client_running = false
  State.launched_by_us = false
  State.service_ip = nil
  State.service_port = nil
end

function State.update()
  State.torrents = {}
  if not State.client_running then
    return false
  end

  local cmd = mp.command_native({
    name = "subprocess",
    playback_only = false,
    capture_stdout = true,
    capture_stderr = true,
    args = { "curl", "-s", "--connect-timeout", "3", "http://" .. State.service_ip .. ":" .. State.service_port .. "/torrents" }
  })

  if cmd.status ~= 0 then
    State.client_running = false
    State.launched_by_us = false
    msg.error("error updating client state: subprocess status is", cmd.status)
    return false
  end

  local t = utils.parse_json(cmd.stdout)
  for _, v in pairs(t) do
    table.insert(State.torrents, {
      InfoHash = v.InfoHash,
      Name = v.Name,
      Files = v.Files,
      Length = v.Length,
      Playlist = v.Playlist,
      MimeType = v.MimeType
    })
  end

  table.sort(State.torrents, function(a, b)
    return a.Name:lower() < b.Name:lower()
  end)

  return true
end

return State
