PLATFORM = mp.get_property("platform", "")
BINARY_SUFFIX = PLATFORM == "windows" and ".exe" or ""

-- Utils
local options = require("mp.options")


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
      if not State.client_running then
        Client.start()
      end

      if State.client_running then
        local playlist = Client.add(path)
        if playlist then
          State.update()
          local infohash = playlist:match("(" .. string.rep("%x", 40) .. ")/")
          for _, v in pairs(State.torrents) do
            if v.InfoHash == infohash then
              local media_files = {}
              for _, file in pairs(v.Files) do
                if string.match(file.MimeType, "video") or string.match(file.MimeType, "audio") then
                  table.insert(media_files, file)
                end
              end
              mp.set_property("stream-open-filename", "memory://" .. Menu.generate_playlist(media_files))
              return
            end
          end
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

  State.find_service()
  mp.add_periodic_timer(15, function()
    State.find_service()
  end)

  if not State.client_running and Config.opts.StartClientOnMpvLaunch then
    Client.start()
  end
end

init()
