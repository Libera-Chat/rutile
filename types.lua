--- @meta

snowcone = {}

--- @param label string
--- @param format string
--- @param ... (string | number)
function status(label, format, ...) end

--- @class PluginManager
PluginManager = {}

--- @param name string
--- @param ext string
--- @return string
function PluginManager:plugin_path(name, ext) return "" end

plugin_manager = PluginManager

myopenssl = {}

--- @param base64 string
--- @return string
function myopenssl.from_base64(base64) return "" end

--- @class (exact) IrcState
--- @field phase string
--- @field nick string?
IrcState = {
    phase = "",
    nick = "",

}

--- @param name string
--- @return table | nil
function IrcState:get_channel(name) return {} end

--- @type IrcState
irc_state = IrcState

--- @type table<any, string>
background_resources = {}

--- @class (exact) Irc: string[]
--- @field nick string
--- @field user string
--- @field host string
--- @field command string
--- @field tags table<string, string|true>
--- @field source string?
Irc = {}

--- @class Project
--- @field authorized table<string, true>
--- @field events table<string, true>
--- @field channel string
Project = {}

--- @class (exact) Configuration
--- @field port integer
--- @field credentials table<string, string>
--- @field debug boolean
--- @field projects table<string, Project>
Configuration = {}