local msg = require("mp.msg")
local utils = require("mp.utils")
local http = require("socket.http")
local ltn12 = require("ltn12")
local mdns = require("mdns")

mdns.socket.setup = function(self)
        local socket = require('socket')
        self.udp = socket.udp4()
        assert(self.udp:setoption('reuseaddr', true))
        assert(self.udp:setsockname('*', 5353))
        assert(self.udp:setoption('ip-add-membership', { interface = '*', multiaddr = self.PEER.IP }))
        assert(self.udp:settimeout(0.1))
end

local State = {
  client_running = false,
  launched_by_us = false,
  torrents = {},
  service_ip = false,
  service_port = false
}

function State.find_service()
  local service = '_libtorrentmpv._tcp'
  local found = mdns.query(service, 0.3)
  for _, v in pairs(found) do
    if v.ipv4 then
      State.client_running = true
      State.service_ip = v.ipv4
      State.service_port = v.port
      return
    end
  end
  State.client_running = false
  State.launched_by_us = false
  State.service_ip = false
  State.service_port = false
end

function State.update()
  State.torrents = {}
  if not State.client_running then
    return false
  end

  local url = "http://" .. State.service_ip .. ":" .. State.service_port .. "/torrents"
  local response_body = {}
  local res, code = http.request {
    url = url,
    sink = ltn12.sink.table(response_body),
    method = "GET"
  }

  if code ~= 200 then
    State.client_running = false
    msg.error("error updating client state: http status is", code)
    return false
  end

  local body = table.concat(response_body)
  local t = utils.parse_json(body)
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
