# GitHub notification plugin for snowcone

Rutile listens for GitHub webhook notifications and announces them to IRC channels.

## Client configuration

Enable this plugin in `~/.config/snowcone/settings.toml`

```toml
[plugins]
modules=['github']
```

Credentials and projects are configured offline in `~/.config/snowcone/plugins/github.dat`.
After changing this file run `/reload` in snowcone.

## Online configuration

rutile responds to the following commands on IRC in private message:

### `help [command]`

List available commands or print documentation about a specific command.

### `projects`

List all the configured projects

### `events <project>`

List all the events enabled for a project

### `event_on <project> <event>`

Announce this event on a project in the project's configured channel

### `event_off <project> <event>`

Stop announcing an event for a project
