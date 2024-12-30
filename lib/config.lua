local msg = require("mp.msg")
local utils = require("mp.utils")

local Config = {
  opts = {
    address = "0.0.0.0",
    port = 1337,
    ["save-path"] = os.getenv("tmp"),
    StartClientOnMpvLaunch = true,
    -- CloseClientOnMpvExit = true,
    -- CloseClientOnNoTorrentFiles = false
  }
}

function Config.get_client_args()
  local args = {}
  for i, v in pairs(Config.opts) do
    local first_char = i:sub(1, 1)
    if string.lower(first_char) == first_char then
      args[#args + 1] = "--" .. i .. "=" .. tostring(v)
    end
  end
  return args
end

function Config.save_opts()
  local function lua_to_mpv(value)
    if type(value) == "boolean" then
      return value and "yes" or "no"
    else
      return value
    end
  end

  local mpv_dirpath = string.gsub(mp.get_script_directory(), "scripts[\\/][^\\/]+", "")
  local config_filepath = utils.join_path(utils.join_path(mpv_dirpath, "script-opts"),
    string.format('%s.conf', mp.get_script_name()))
  local handle = io.open(config_filepath, 'w')

  if handle ~= nil then
    for i, v in pairs(Config.opts) do
      handle:write(string.format("%s=%s\n", i, lua_to_mpv(v)))
    end
  else
    msg.error("error saving script config")
    return false
  end

  return true
end

return Config
