-- Snowcone Plugin for Processing GitHub Events into IRC Notifications
--
-- This plugin processes GitHub webhook events and formats them into IRC notifications.
-- For more information on GitHub webhook events and payloads, visit:
-- https://docs.github.com/en/webhooks/webhook-events-and-payloads
--
-- Author: Eric Mertens (glguy@libera.chat)
-- License: ISC
-- Copyright © 2024 Eric Mertens

--- @alias headers table<string, string>
--- @alias replacement (table<string, replacement>|string|number)

--#region IMPORTS

local file = require 'pl.file'
local json = require 'json'
local mkcommand = require 'utils.mkcommand'
local N = require 'utils.numerics'
local path = require 'pl.path'
local scrub = require 'utils.scrub'
local send = require 'utils.send'
local Set = require 'pl.Set'
local sha256 = myopenssl.get_digest 'sha256'
local tablex = require 'pl.tablex'

--- Snowcone plugin configuration
--- @type Configuration, fun(configuration: Configuration)
local config, save_config = ...

-- Install a default configuration if one doesn't exist
if not config then
    config = {
        projects = {},
        debug = false,
        credentials = {},
        port = 8000,
    }
    save_config(config)
end

--#endregion
--#region MESSAGE FORMATTING

--- Generates a hexadecimal representation of a hash from a given string.
--- @param bytes string The input string to be hashed.
--- @return string
local function hexbytes(bytes)
    local hex_representation = {}
    for i = 1, #bytes do
        hex_representation[i] = string.format('%02x', bytes:byte(i))
    end
    return table.concat(hex_representation)
end

--- Ensure that a string isn't longer than a given limit, truncate if needed
--- @param str string String to truncate
--- @param limit integer Maximum length of returned string
--- @return string
local function truncate(str, limit)
    if #str > limit then
        return str:sub(1, limit - 1) .. '…'
    else
        return str
    end
end

--- Actions indicate a workflow has transitioned from closed to open
local resume_actions = Set{
    "reopened"
}

--- Actions that initiate a new workflow
local creation_actions = Set{
    "created", "opened",
}

--- Actions that end a workflow
local negative_actions = Set{
    "deleted", "closed", "removed"
}

--- Actions that indicate forward progress or completion of a workflow
local progress_actions = Set{
    "merged", "assigned", "resolved", "pushed", "approved"
}

--- Actions that should draw special attention
local important_actions = Set{
    "force pushed"
}

--- Render actions seen in GitHub API into IRC formatted strings
--- @param action string Action name
--- @return string text IRC-formatted, human-readable text
local function format_action(action)
    action = action:gsub('_', ' ')
    if progress_actions[action] then
        return '\x02\x0302' .. action .. '\x0f'
    elseif creation_actions[action] then
        return '\x02\x0303' .. action .. '\x0f'
    elseif negative_actions[action] then
        return '\x02\x0304' .. action .. '\x0f'
    elseif important_actions[action] then
        return '\x02\x0305' .. action .. '\x0f'
    elseif resume_actions[action] then
        return '\x02\x0306' .. action .. '\x0f'
    else
        return '\x02' .. action .. '\x0f'
    end
end

--- Given a replacement and an interpolation string evaluate all of the
--- interpolation placeholders.
---
--- Placeholders format: '{' '#'? ('.' <field name>)* '}'
--- Leading '#' uses raw replacement, otherwise control characters are replaced.
--- Each '.' <field name> causes the replacement value to be indexed.
--- Final replacement values are converted to string and truncated.
---
--- @param obj replacement Replacements
--- @param str string Format string
--- @return string
local function interpolate(obj, str)
    return (str:gsub('{(#?%.[._%a]*)}', function(expr)
        local cursor, raw, rest = obj, expr:match '^(#?)(.*)$'
        while rest ~= '' do
            local key
            key, rest = rest:match '^%.([_%a]*)(.*)$'
            cursor = cursor[key]
        end
        cursor = truncate(tostring(cursor), 100)
        if raw == '' then
            cursor = scrub(cursor)
        end
        return cursor
    end))
end

--- Functions for generating an announcement message for each supported event type
--- @type table<string, fun(body: table): string?>
local formatters = {
    push = function(body)
        local target = body.ref:match('^refs/heads/(.*)$')
        if not target then
            target = body.ref:match('^refs/tags/(.*)$')
            if target then
                target = 'tag ' .. target
            end
        end
        if target and body.head_commit.message then
            body.x_target = target
            body.x_after = body.after:sub(1,9)
            body.x_action = format_action(body.forced and 'force pushed' or 'pushed')
            return interpolate(body,
                '{.repository.full_name}: \x02{.sender.login}\x02 {#.x_action} {.x_after} to \x0302{.x_target}\x0f: \z
                {.head_commit.message}')
        end
    end,
    issue_comment = function(body)
        body.x_action = format_action(body.action)
        return interpolate(body,
            '{.repository.full_name}: \x02{.sender.login}\x02 {#.x_action} comment on \z
            issue #{.issue.number} ({.issue.title}): \z
            {.comment.body} - \x0305{.issue.html_url}')
    end,
    issues = function(body)
        if body.action == 'closed' and body.issue.state_reason == 'completed' then
            body.x_action = format_action('resolved')
        else
            body.x_action = format_action(body.action)
        end
        return interpolate(body,
            '{.repository.full_name}: \x02{.sender.login}\x02 {#.x_action} \z
            issue #{.issue.number}: \x02{.issue.title}\x02 - \x0305{.issue.html_url}')
    end,
    pull_request_review = function(body)
        if body.action == 'submitted' and body.review.state == 'approved' then
            body.x_action = format_action('approved')
            return interpolate(body,
                '{.repository.full_name}: \x02{.sender.login}\x02 {#.x_action} \z
                PR #{.pull_request.number} ({.pull_request.title}): \z
                {.review.body} - \x0305{.pull_request.html_url}')
        end

        body.x_action = format_action(body.action)
        return interpolate(body,
            '{.repository.full_name}: \x02{.sender.login}\x02 {#.x_action} review on \z
            PR #{.pull_request.number} ({.pull_request.title}): \z
            {.review.body} - \x0305{.pull_request.html_url}')
    end,
    pull_request_review_comment = function(body)
        body.x_action = format_action(body.action)
        return interpolate(body,
            '{.repository.full_name}: \x02{.sender.login}\x02 {#.x_action} comment on \z
            PR #{.pull_request.number} ({.pull_request.title}): \z
            {.comment.body} - \x0305{.pull_request.html_url}')
    end,
    pull_request = function(body)
        if body.action == 'closed' and body.pull_request.merged then
            body.x_action = format_action('merged')
        else
            body.x_action = format_action(body.action)
        end
        return interpolate(body,
            '{.repository.full_name}: \x02{.sender.login}\x02 {#.x_action} \z
            PR #{.pull_request.number}: \z
            {.pull_request.title} - \x0305{.pull_request.html_url}')
    end,

    -- Special event for r10k deployments
    deploy = function(body)
        return interpolate(body,
            '{.repository.full_name}: environment \x02{.environment}\x02 deployed')
    end,
}

--#endregion
--#region FILESYSTEM HELPERS

--- Compute the application's cache directory respecting XDG conventions
--- @return string path cache directory path
local function cache_dir()
    local xdg_cache_home = os.getenv 'XDG_CACHE_HOME'
    if xdg_cache_home ~= nil and xdg_cache_home ~= '' then
        return path.join(xdg_cache_home, 'snowcone')
    end
    local home = assert(os.getenv 'HOME')
    return path.join(home, '.cache', 'snowcone')
end

--#endregion
--#region HTTP LOGIC
--#region HTTP REPLIES

local plain_text_headers = {['Content-Type'] = 'text/plain'}

local function reply_ok(body)
    return 200, body, plain_text_headers
end

local function reply_no_content()
    return 204, '', plain_text_headers
end

local function reply_bad_request()
    return 400, 'bad request', plain_text_headers
end

local function reply_unauthorized()
    return 401, 'unauthorized', plain_text_headers
end

local function reply_forbidden()
    return 403, 'forbidden', plain_text_headers
end

local function reply_not_found()
    return 404, 'not found', plain_text_headers
end

local function reply_method_not_allowed()
    return 405, 'method not allowed', plain_text_headers
end

--#endregion

--- Process a raw JSON body as a GitHub notification.
--- @param authid string|nil Authentication identifier or nil to bypass check
--- @param event string Event name
--- @param raw_body string JSON encoded object
--- @return number status HTTP response status code
--- @return string body HTTP response body
--- @return headers headers HTTP response headers
local function do_notify(authid, event, raw_body)
    local body = json.decode(raw_body)
    local full_name = body.repository and body.repository.full_name or body.organization.login
    local project = config.projects[full_name]

    if authid and not project.authorized[authid] then
        return reply_forbidden()
    end

    -- Save body for debugging and replay, but delay saving the event until we've checked it's valid
    if config.debug then
        file.write(
            path.join(cache_dir(), 'gh-notify-' .. event .. '-' .. hexbytes(sha256:digest(raw_body)) .. '.json'),
            raw_body)
    end

    -- <event> or <event>:<action>
    local full_event = event
    if body.action then
        full_event = full_event .. ':' .. body.action
    end

    -- If a message is called for, store it here
    local message
    if project and project.events[full_event] then
        local formatter = formatters[event]
        if formatter then
            message = formatter(body)
        else
            status('github', 'Error: No formatter for enabled event: %s', event)
        end
    end

    if message then
        send('NOTICE', project.channel, message)
        status('github', 'Announcing %s %s %s', full_name, full_event, project.channel)
    else
        status('github', 'Ignoring %s %s', full_name, full_event)
    end
    return reply_no_content()
end

--- Map of target patterns to response handler functions.
--- Each handler expects: HTTP headers, HTTP method, HTTP body, pattern matches...
--- @type table<string, fun(headers: headers, method: string, body: string, ...: string): number, string, headers>
local routes = {
    ['^/notify/(.*)$'] = function(headers, method, body, notify_name)
        if method ~= 'POST' then
            return reply_method_not_allowed()
        end

        do -- enforce authentication
            local secret = config.credentials[notify_name]
            local signature = headers['x-hub-signature-256']
            local expected_signature = 'sha256=' .. hexbytes(sha256:hmac(body, secret))
            if expected_signature ~= signature then
                return reply_unauthorized()
            end
        end

        local event = headers['x-github-event']
        if not event then
            return reply_bad_request()
        end

        return do_notify(notify_name, event, body)
    end,

    ['^/source$'] = function(_, method)
        if method ~= 'GET' then
            return reply_method_not_allowed()
        end
        return reply_ok(file.read(plugin_manager:plugin_path('github', 'lua')))
    end,

    --[[
    ['^/auth$'] = function(headers, method)
        local auth = headers['authorization']
        if auth then
            local user, pass = assert(snowcone.from_base64(auth:match '^Basic ([a-zA-Z0-9+/]*=?=?)$')):match '^([^:]*):(.*)$'
            return reply_ok(string.format('%s %s', user, pass))
        end
        return 401, 'not authorized', {['Content-Type'] = 'text/plain', ['WWW-Authenticate'] = 'Basic realm=rutile'}
    end,
    ]]
}

--- Callback logic for an httpd event
--- @param method? string HTTP request method or nil
--- @param target string HTTP request path or error kind
--- @param body string HTTP request body or error message
--- @param headers? headers HTTP request headers or nil
--- @return number? status HTTP reponse status
--- @return string? body HTTP response bode
--- @return headers? headers HTTP response headers
local function on_http(method, target, body, headers)

    -- No method means target:error_kind body:error_message
    if method == nil then
        status('github', 'http error: %s %s', target, body)
        return
    end

    for pattern, handler in pairs(routes) do
        local matches = {target:match(pattern)}
        if next(matches) then
            return handler(headers or {}, method, body, table.unpack(matches))
        end
    end

    return reply_not_found()
end

--#endregion
--#region IRC LOGIC

--- Issue a JOIN command for any channels we're not in that we need to be able to announce in.
local function join_channels()
    local channels = {}
    for _, project in pairs(config.projects) do
        local channel = project.channel
        if not irc_state:get_channel(channel) then
            channels[channel] = true
        end
    end
    if next(channels) then
        -- we shouldn't be in *that many* channels that we need to break this up
        send('JOIN', table.concat(tablex.keys(channels), ','))
    end
end

--- All the online documentation content
--- @type table<string, string[]>
local help_strings = {
    projects = {'projects - List all of the configured project names'},
    events = {'events <project> - List all of the configured events for the project'},
    event_on = {'event_on <project> <event>[:<action>] - Start announcing an event for a project'},
    event_off = {'event_off <project> <event>[:<action>] - Stop announcing an event for a project'},
    help = {'help [command] - Print help for a command or list the available commands'},
}

local function keys_as_lines(tab, prefix)
    local lines = {}
    local acc = {}
    local n = 0

    if prefix then
        table.insert(acc, prefix)
    end

    for name in tablex.sort(tab) do
        if next(acc) and #name + 1 + n > 400 then
            table.insert(lines, table.concat(acc, ' '))
            acc = {}
            n = 0
        end

        table.insert(acc, name)
        n = n + #name
    end

    if next(acc) then
        table.insert(lines, table.concat(acc, ' '))
    end

    return lines
end

--- Commands available to staff members chatting with the bot in private message
local irc_commands = {
    --- List all the commands or provide help text for a specific command
    --- @type fun(command: string?): string[]
    help = function(command)
        local doc = help_strings[command]
        if doc then
            return doc
        else
            return keys_as_lines(help_strings, 'Commands:')
        end
    end,

    --- Enable reporting an event for a specific repository
    --- @type fun(repo: string, event: string): string[]
    event_on = function(repo, event)
        -- Check if we have a formatter for this event
        local prefix = event:match '^[^:]*'
        if not formatters[prefix] then
            return {'event not yet supported'}
        end

        local project = config.projects[repo]
        if not project then
            return {'no such project'}
        end

        local old = project.events[event]
        if old then
            return {'already enabled'}
        end

        project.events[event] = true
        save_config(config)
        return {'event enabled'}
    end,

    --- Disable reporting an event for a specific repository
    --- @type fun(repo: string, event: string): string[]
    event_off = function(repo, event)
        local project = config.projects[repo]
        if not project then
            return {'no such project'}
        end

        local old = project.events[event]
        if not old then
            return {'already disabled'}
        end

        project.events[event] = nil
        save_config(config)
        return {'event disabled'}
    end,

    --- List all the configured projects
    --- @type fun(): string[]
    projects = function()
        return keys_as_lines(config.projects, 'Projects:')
    end,

    --- List all the events enabled for a particular project
    --- @type fun(repo: string): string[]
    events = function(repo)
        local project = config.projects[repo]
        if not project then
            return {'no such project'}
        end
        return keys_as_lines(project.events, 'Events:')
    end,
}

--- Event handlers for incoming IRC messages
--- @type table<number | string, fun(irc: Irc)>
local irc_handlers = {
    --- Listen for private message commands from staff
    PRIVMSG = function(irc)
        -- Only accept commands from staff
        if not irc.host:match '^libera/staff/' then return end

        -- Only accept direct messages
        if irc[1] ~= irc_state.nick then return end
        local args = irc[2]:split()
        local handler = irc_commands[args[1]]
        if handler then
            status('github', 'Command from %s@%s: %s', irc.nick, irc.host, irc[2])
            local reply = handler(table.unpack(args, 2))
            for _, line in ipairs(reply) do
                send('NOTICE', irc.nick, line)
            end
        end
    end,

    --- Join channels when we transition to a connected state
    [N.RPL_WELCOME] = function()
      join_channels()
    end,
}

--#endregion
--#region STARTUP SEQUENCE

-- Tear down previous instantiation, if any
if GITHUB_HTTPD then
    GITHUB_HTTPD:close()
    background_resources[GITHUB_HTTPD] = nil
end

-- start up new httpd
GITHUB_HTTPD = snowcone.start_httpd(config.port, on_http)
background_resources[GITHUB_HTTPD] = 'close'

-- When the plugin (re)loads and we're already connected then
-- make sure we're in all the right channels.
if irc_state and irc_state.phase == 'connected' then
    join_channels()
end

return {
    --- plugin name
    name = "github",

    --- IRC command logic
    --- @type fun(irc: Irc)
    irc = function(irc)
        local handler = irc_handlers[irc.command]
        if handler then
            handler(irc)
        end
    end,

    --- in-client commands
    commands = {
        --- replay an event using a cached request body
        gh_replay = mkcommand('$g $g', function(event, name)
            do_notify(nil, event, file.read(path.join(cache_dir(), name)))
        end),

        --- enable saving request bodies for inspection and replay
        gh_debug_on = mkcommand('', function()
            config.debug = true
            save_config(config)
        end),

        --- disables debug mode
        gh_debug_off = mkcommand('', function()
            config.debug = false
            save_config(config)
        end),

        gh_set_credential = mkcommand('$g $g', function(authid, secret)
            config.credentials[authid] = secret
            save_config(config)
        end),

        gh_drop_credential = mkcommand('$g', function(authid)
            if not config.credentials[authid] then
                error 'no such credential'
            end
            config.credentials[authid] = nil
            for _, project in pairs(config.projects) do
                project.authorized[authid] = nil
            end
            save_config(config)
        end),

        gh_authorize = mkcommand('$g $g', function(repo, authid)
            local project = config.projects[repo]
            if not project then
                error 'no such project'
            end
            if not config.credentials[authid] then
                error 'no such authid'
            end
            project.authorized[authid] = true
            save_config(config)
        end),

        gh_deauthorize = mkcommand('$g $g', function(repo, authid)
            local project = config.projects[repo]
            if not project then
                error 'no such project'
            end
            project.authorized[authid] = nil
            save_config(config)
        end),

        gh_add_project = mkcommand('$g $g', function(repo, channel)
            if config.projects[repo] then
                error 'project exists'
            end
            config.projects[repo] = {
                channel = channel,
                authorized = {},
                events = {},
            }
            save_config(config)
        end),

        gh_set_channel = mkcommand('$g $g', function(repo, channel)
            if not config.projects[repo] then
                error 'no such project'
            end
            config.projects[repo].channel = channel
            save_config(config)
            join_channels()
        end),

        gh_drop_project = mkcommand('$g', function(repo, channel)
            if not config.projects[repo] then
                error 'no such project'
            end
            config.projects[repo] = nil
            save_config(config)
        end),

        gh_event_on = mkcommand('$g $g', function(repo, event)
            if not config.projects[repo] then
                error 'no such project'
            end
            config.projects[repo].events[event] = true
            save_config(config)
        end),

        gh_event_off = mkcommand('$g $g', function(repo, event)
            if not config.projects[repo] then
                error 'no such project'
            end
            config.projects[repo].events[event] = nil
            save_config(config)
        end),

        gh_set_port = mkcommand('$i', function(port)
            if port <= 0 then
                error 'bad port number'
            end
            config.port = port
            save_config(config)
        end),
    },
}

--#endregion
