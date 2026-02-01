# LinkStash API

This document describes the API endpoint that the ash application sends link data to.

## Endpoint

`POST /api/add`

## Headers

- `Authorization: Bearer <token>` - Required authentication token
- `Content-Type: application/json` - Content type

## Request Body

```json
{
  "link": {
    "url": "https://example.com",
    "submittedBy": "@user:matrix.org"
  },
  "room": {
    "id": "!roomid:matrix.org",
    "comment": "room name"
  }
}
```

### Fields

- `link.url` (string, required): The URL of the link
- `link.submittedBy` (string, optional): Matrix user ID of the person who submitted the link (only included if `sendUser` is true in config)
- `room.id` (string, optional): Matrix room ID (only included if `sendTopic` is true in config)
- `room.comment` (string, optional): Room comment/name (only included if `sendTopic` is true in config)

## Example curl command

```bash
curl -X POST "https://linkstash.hsp-ec.xyz/api/add" \
  -H "Authorization: Bearer mentor-here" \
  -H "Content-Type: application/json" \
  -d '{
    "link": {
      "url": "https://example.com",
      "submittedBy": "@user:matrix.org"
    },
    "room": {
      "id": "!roomid:matrix.org",
      "comment": "room name"
    }
  }'
```

## Configuration

The ash application sends this data based on configuration flags in `config.json`:

- `sendUser`: Include the `submittedBy` field
- `sendTopic`: Include the `room` object

Both flags are optional and can be set per room.</content>
<parameter name="filePath">api.md