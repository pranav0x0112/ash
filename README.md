# ash

> a minimal [matrix] message watcher and link extractor

# ash

> a minimal [matrix] message watcher and link extractor

## Bot commands (bot.json)

You can configure bot commands in `bot.json`. Commands can be HTTP-backed, static responses, or use special handlers. Example commands included:

- `/bot hi` or just `/bot` — returns a greeting
- `/bot joke` — uses icanhazdadjoke API (returns the `joke` field)
- `/bot catfact` — uses catfact.ninja API (returns the `fact` field)
- `/bot summary` — fetches recent articles from linkstash and summarizes them using Groq AI
- `/bot gork <message>` — responds to queries using Groq AI (alias: `@gork <message>`)

Commands can also be configured with static responses using the `response` field.

Add or change commands in `bot.json` and set `BOT_CONFIG_PATH` in `config.json` if you place it elsewhere. The bot will prefix responses using `BOT_REPLY_LABEL` in `config.json` (defaults to `[BOT]\n`).

### Room-specific bot configuration

Bot commands are enabled per room via the `allowedCommands` array in `config.json`:

- `"allowedCommands": []` — Enable bot with all commands allowed
- `"allowedCommands": ["summary", "joke"]` — Enable bot with only specific commands
- Omit `allowedCommands` — Bot disabled in that room

The `hi` command is always allowed in all rooms.

This allows fine-grained control over which commands are available in each room.

pairs nicely with [lava](https://polarhive.net/lava)

> lava is a web clipping tool that can run as a server or daemon to automatically populate your Obsidian clippings directory with fresh parsed md from URLs.

## Setup

1. Install Go 1.25+ and SQLite.
2. Clone the repo.
3. Copy `config.json` and edit with your Matrix credentials.
4. Run `make` to build and run.

## Structure

- `ash.go`: Main application logic
- `bot.go`: Bot command handling
- `db/`: Database schema files
- `data/`: Runtime data (SQLite, exports)
- `config.json`: Configuration file
- `bot.json`: Bot commands configuration

## Configuration

Edit `config.json`:

- `MATRIX_HOMESERVER`: Your Matrix server URL
- `MATRIX_USER`: Your Matrix user ID
- `MATRIX_PASSWORD`: Password
- `MATRIX_RECOVERY_KEY`: For E2EE verification
- `MATRIX_ROOM_ID`: Array of rooms to watch, each with:
  - `id`: Room ID
  - `comment`: Human-readable name
  - `hook`: Optional webhook URL for link processing
  - `key`: Webhook auth key
  - `sendUser`/`sendTopic`: Whether to include user/topic in webhooks
  - `allowedCommands`: Array of allowed bot commands (empty = all, omit = disabled)
- `BOT_REPLY_LABEL`: Bot response prefix (default: `[BOT]\n`)
- `LINKSTASH_URL`: Base URL for linkstash service (used in summary bot)
- `GROQ_API_KEY`: API key for Groq AI (required for summary and gork commands)
- `MATRIX_DEVICE_NAME`: Device name
- `DEBUG`: Enable debug logging

## Usage

- `make`: Build and run
- `make build`: Build only
- `make clean`: Clean build artifacts

Links are exported to `data/links.json`.