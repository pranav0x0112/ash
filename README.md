# ash

> a minimal [matrix] message watcher and link extractor

pairs nicely with [lava](https://polarhive.net/lava)

> lava is a web clipping tool that can run as a server or daemon to automatically populate your Obsidian clippings directory with fresh parsed md from URLs.

## Setup

1. Install Go 1.25+ and SQLite.
2. Clone the repo.
3. Copy `config.json` and edit with your Matrix credentials.
4. Run `make` to build and run.

## Structure

- `ash.go`: Main application logic
- `db/`: Database schema files
- `data/`: Runtime data (SQLite, exports)
- `internal/`: Internal packages (config, db, matrix)

## Configuration

Edit `config.json`:

- `MATRIX_HOMESERVER`: Your Matrix server URL
- `MATRIX_USER`: Your Matrix user ID
- `MATRIX_PASSWORD`: Password
- `MATRIX_RECOVERY_KEY`: For E2EE verification
- `MATRIX_ROOM_ID`: Array of rooms to watch
- `MATRIX_DEVICE_NAME`: Device name
- `DEBUG`: Enable debug logging

## Usage

- `make`: Build and run
- `make build`: Build only
- `make clean`: Clean build artifacts

Links are exported to `data/links.json`.