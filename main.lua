-- Utils
local options = require("mp.options")

PLATFORM = mp.get_property("platform", "")

local Config = require("lib/config")
local State = require("lib/state")
local Client = require("lib/client")
local Menu = require("lib/menu")

-- Constants
local TORRENT_PATTERNS = { "%.torrent$", "^magnet:%?xt=urn:btih:", "^" .. string.rep("%x", 40) .. "$" }
local EXCLUDE_PATTERNS = { "127%.0%.0%.1", "/torrents/" }

-- Event handlers
local function on_file_loaded()
  local path = mp.get_property("stream-open-filename", "")

  for _, pattern in ipairs(EXCLUDE_PATTERNS) do
    if path:find(pattern) then return end
  end

  for _, pattern in ipairs(TORRENT_PATTERNS) do
    if path:find(pattern) then
      if Client.start() then
        local infohash = Client.add(path)
        if infohash then
          State.update()
          mp.set_property("stream-open-filename", "http://127.0.0.1:" .. Config.opts.port .. "/torrents/" .. infohash)
          return
        end
      end
      break
    end
  end

  -- if next(State.torrents) == nil and Config.opts.CloseClientOnNoTorrentFiles then
  --   Client.close()
  -- end
end

-- Script initialization
local function init()
  options.read_options(Config.opts)
  mp.register_event("shutdown", function() options.read_options(Config.opts) end)

  -- Register menu command
  mp.add_key_binding("Alt+t", "toggle-torrent-menu", function()
    Menu.show()
  end)

  -- Register menu callback handler
  mp.register_script_message("menu-callback", function(json) Menu.handle_callback(json) end)

  -- Register MPV event handlers
  mp.add_hook("on_load", 50, on_file_loaded)

  -- if Config.opts.CloseClientOnMpvExit then
  --   mp.register_event("shutdown", function() Client.close() end)
  -- end

  if Config.opts.StartClientOnMpvLaunch then
    Client.start()
  elseif State.is_running() then
    State.client_running = true
    -- State.launched_by_us = false
  end
end

init()
