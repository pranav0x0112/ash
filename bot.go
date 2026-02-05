package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// BotCommand describes a bot command that can return text or images
type BotCommand struct {
	Method       string                 `json:"method,omitempty"`
	URL          string                 `json:"url"`
	Headers      map[string]string      `json:"headers,omitempty"`
	JSONPath     string                 `json:"json_path,omitempty"`
	ResponseType string                 `json:"response_type,omitempty"` // "text", "json", or "image" (optional)
	Handler      string                 `json:"handler,omitempty"`       // "http", "quack", "meow", "deepfry", "joke" (optional)
	Params       map[string]interface{} `json:"params,omitempty"`        // Additional parameters for handlers
}

// BotConfig is the structure of bot.json
type BotConfig struct {
	Label    string                `json:"label,omitempty"`
	Commands map[string]BotCommand `json:"commands,omitempty"`
}

// LoadBotConfig reads and parses the bot config file.
func LoadBotConfig(path string) (*BotConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	var bc BotConfig
	dec := json.NewDecoder(f)
	if err := dec.Decode(&bc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &bc, nil
}

// FetchBotCommand executes the configured command and returns a string to post.
func FetchBotCommand(ctx context.Context, c *BotCommand, linkstashURL string, ev *event.Event, matrixClient *mautrix.Client) (string, error) {
	// Check if this command uses a special handler
	if c.Handler != "" {
		switch c.Handler {
		case "quack":
			return handleQuackCommand(ctx, ev, matrixClient, c)
		case "meow":
			return handleMeowCommand(ctx, ev, matrixClient, c)
		case "deepfry":
			return handleDeepfryCommand(ctx, ev, matrixClient, c)
		case "joke":
			return handleJokeCommand(ctx, c)
		default:
			return "", fmt.Errorf("unknown handler: %s", c.Handler)
		}
	}

	// Original HTTP-based command logic
	method := c.Method
	if method == "" {
		method = "GET"
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL, nil)
	if err != nil {
		return "", err
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	// Default User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "ash-bot (https://github.com/polarhive/ash)")
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// If JSON path provided, try to parse
	if c.JSONPath != "" || strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		var j interface{}
		if err := json.Unmarshal(bodyBytes, &j); err != nil {
			// If parsing fails but we expected json, return raw body as fallback
			return strings.TrimSpace(string(bodyBytes)), nil
		}
		v := extractJSONPath(j, c.JSONPath)
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s), nil
		}
		// Check if it's an array of posts (for summary)
		if arr, ok := v.([]interface{}); ok {
			return formatPosts(arr, linkstashURL), nil
		}
		// try to marshal the value to string
		if v != nil {
			b, _ := json.Marshal(v)
			return strings.TrimSpace(string(b)), nil
		}
		return "", fmt.Errorf("no value found at path: %s", c.JSONPath)
	}
	// Default: return body as text
	return strings.TrimSpace(string(bodyBytes)), nil
}

// Very small helper to extract keys separated by '.' from a parsed JSON value.
func extractJSONPath(root interface{}, path string) interface{} {
	if path == "" {
		return root
	}
	parts := strings.Split(path, ".")
	cur := root
	for _, p := range parts {
		switch v := cur.(type) {
		case map[string]interface{}:
			cur = v[p]
		default:
			return nil
		}
	}
	return cur
}

// formatPosts formats an array of post objects into a readable string.
func formatPosts(posts []interface{}, linkstashURL string) string {
	var sb strings.Builder
	limit := 5
	if len(posts) < limit {
		limit = len(posts)
	}
	for i := 0; i < limit; i++ {
		p := posts[i]
		if m, ok := p.(map[string]interface{}); ok {
			title, _ := m["title"].(string)
			url, _ := m["url"].(string)
			if title != "" && url != "" {
				sb.WriteString(fmt.Sprintf("- %s (%s)\n", title, url))
			}
		}
	}
	sb.WriteString(fmt.Sprintf("\nSee full list: %s", linkstashURL))
	return sb.String()
}

// handleDeepfryCommand processes a deepfry command by finding image attachments and applying deepfry effects
func handleDeepfryCommand(ctx context.Context, ev *event.Event, matrixClient *mautrix.Client, cmd *BotCommand) (string, error) {
	log.Debug().Str("event_id", string(ev.ID)).Str("event_type", ev.Type.String()).Msg("processing deepfry command")

	// Parse the message content
	if ev.Content.Raw != nil {
		if err := ev.Content.ParseRaw(ev.Type); err != nil {
			if !strings.Contains(err.Error(), "already parsed") {
				return "", fmt.Errorf("failed to parse event: %w", err)
			}
		}
	}

	msg := ev.Content.AsMessage()
	if msg == nil {
		return "", fmt.Errorf("not a message event")
	}

	log.Debug().Str("msg_type", string(msg.MsgType)).Interface("relates_to", msg.RelatesTo).Msg("message details")
	var imageMsg *event.MessageEventContent

	if msg.MsgType == event.MsgImage || msg.MsgType == "m.sticker" || msg.URL != "" || msg.File != nil {
		imageMsg = msg
		log.Debug().Interface("image_info", imageMsg.Info).Str("has_file", fmt.Sprintf("%v", imageMsg.File != nil)).Str("has_url", fmt.Sprintf("%v", imageMsg.URL != "")).Msg("image message content")
	} else if msg.RelatesTo != nil && msg.RelatesTo.InReplyTo != nil {
		// This is a reply, fetch the original message
		originalEvent, err := matrixClient.GetEvent(ctx, ev.RoomID, msg.RelatesTo.InReplyTo.EventID)
		if err != nil {
			return "", fmt.Errorf("failed to fetch replied-to message: %w", err)
		}

		// Parse the original event content
		if originalEvent.Content.Raw != nil {
			if err := originalEvent.Content.ParseRaw(originalEvent.Type); err != nil {
				return "", fmt.Errorf("failed to parse original event: %w", err)
			}
		}

		// Decrypt the event if it's encrypted
		if originalEvent.Type == event.EventEncrypted && matrixClient.Crypto != nil {
			log.Debug().Str("event_id", string(originalEvent.ID)).Msg("decrypting replied-to encrypted event")
			decryptedEvent, err := matrixClient.Crypto.Decrypt(ctx, originalEvent)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt replied-to message: %w", err)
			}
			originalEvent = decryptedEvent
			log.Debug().Str("event_id", string(originalEvent.ID)).Msg("successfully decrypted replied-to event")
		} else {
			log.Debug().Str("event_id", string(originalEvent.ID)).Str("event_type", originalEvent.Type.String()).Msg("replied-to event (not encrypted or no crypto)")
		}

		originalMsg := originalEvent.Content.AsMessage()
		if originalMsg != nil && (originalMsg.MsgType == event.MsgImage || originalMsg.MsgType == "m.sticker" || originalMsg.URL != "" || originalMsg.File != nil) {
			imageMsg = originalMsg
			log.Debug().Interface("original_image_info", originalMsg.Info).Str("original_has_file", fmt.Sprintf("%v", originalMsg.File != nil)).Str("original_has_url", fmt.Sprintf("%v", originalMsg.URL != "")).Msg("original image message content")
		}
	}

	if imageMsg == nil {
		return "", fmt.Errorf("no image found - please send an image or reply to one with /bot deepfry")
	}

	// Get the media URL or handle encrypted file
	var mediaURL id.ContentURIString
	var encryptedFile *event.EncryptedFileInfo

	if imageMsg.File != nil {
		// Encrypted media - use the URL from the file info and decrypt later
		mediaURL = imageMsg.File.URL
		encryptedFile = imageMsg.File
		log.Debug().Str("encrypted_media_url", string(mediaURL)).Interface("encrypted_file", imageMsg.File).Msg("using encrypted media URL")
	} else if imageMsg.URL != "" {
		// Unencrypted media - use direct URL
		mediaURL = imageMsg.URL
		log.Debug().Str("media_url", string(mediaURL)).Msg("using direct media URL")
	} else {
		return "", fmt.Errorf("no media URL or encrypted file found")
	}

	// Download the image
	var data []byte
	var err error

	if mediaURL != "" {
		// Download media (may be encrypted or unencrypted)
		parsedURL, err := id.ParseContentURI(string(mediaURL))
		if err != nil {
			return "", fmt.Errorf("failed to parse media URL: %w", err)
		}
		data, err = matrixClient.DownloadBytes(ctx, parsedURL)
		if err != nil {
			return "", fmt.Errorf("failed to download image: %w", err)
		}

		// If this was from an encrypted file, decrypt it
		if encryptedFile != nil {
			log.Debug().Msg("decrypting downloaded encrypted media")
			err = encryptedFile.PrepareForDecryption()
			if err != nil {
				return "", fmt.Errorf("failed to prepare for decryption: %w", err)
			}
			data, err = encryptedFile.Decrypt(data)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt image: %w", err)
			}
			log.Debug().Msg("successfully decrypted media")
		} else {
			log.Debug().Msg("downloaded unencrypted media")
		}
	} else {
		return "", fmt.Errorf("no valid media source found")
	}

	log.Debug().Int("size", len(data)).Msg("downloaded image data")

	// Ensure data/tmp directory exists
	tmpDir := "data/tmp"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Create temporary files
	inputFile, err := os.CreateTemp(tmpDir, "deepfry_input_*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temp input file: %w", err)
	}

	outputFile, err := os.CreateTemp(tmpDir, "deepfry_output_*.jpg")
	if err != nil {
		return "", fmt.Errorf("failed to create temp output file: %w", err)
	}

	// Write downloaded data to input file
	if _, err := inputFile.Write(data); err != nil {
		return "", fmt.Errorf("failed to write image data: %w", err)
	}
	inputFile.Close()

	// Try to detect file type using 'file' command
	fileCmd := exec.Command("file", inputFile.Name())
	fileOutput, err := fileCmd.Output()
	inputPath := inputFile.Name()
	if err == nil {
		log.Debug().Str("file_type", strings.TrimSpace(string(fileOutput))).Msg("detected file type")

		// Determine file extension based on detected type
		typeStr := strings.ToLower(strings.TrimSpace(string(fileOutput)))
		var ext string
		if strings.Contains(typeStr, "jpeg") || strings.Contains(typeStr, "jpg") {
			ext = ".jpg"
		} else if strings.Contains(typeStr, "png") {
			ext = ".png"
		} else if strings.Contains(typeStr, "gif") {
			ext = ".gif"
		} else if strings.Contains(typeStr, "webp") || strings.Contains(typeStr, "web/p") {
			ext = ".webp"
		} else {
			ext = ".png" // default to png if unknown
		}
		newName := strings.TrimSuffix(inputFile.Name(), ".tmp") + ext
		if err := os.Rename(inputFile.Name(), newName); err != nil {
			log.Warn().Err(err).Msg("failed to rename input file")
		} else {
			log.Debug().Str("new_name", newName).Msg("renamed input file with extension")
			inputPath = newName
		}
	} else {
		log.Warn().Err(err).Msg("failed to detect file type")
	}

	// Log first 64 bytes as hex for debugging
	if len(data) > 0 {
		hexLen := 64
		if len(data) < hexLen {
			hexLen = len(data)
		}
		hexDump := fmt.Sprintf("%x", data[:hexLen])
		log.Debug().Str("hex_prefix", hexDump).Int("total_size", len(data)).Msg("file header bytes")
	}

	// Check if the file is actually an image by running identify
	var identifyCmd *exec.Cmd
	var identifyStderr bytes.Buffer

	if exec.Command("magick", "identify", inputPath).Run() == nil {
		identifyCmd = exec.Command("magick", "identify", inputPath)
	} else {
		identifyCmd = exec.Command("identify", inputPath)
	}
	identifyCmd.Stderr = &identifyStderr

	if err := identifyCmd.Run(); err != nil {
		log.Warn().Err(err).Str("stderr", identifyStderr.String()).Str("file", inputPath).Msg("identify failed, attempting conversion anyway")
		// Don't return error, try conversion anyway
	}

	// Apply deepfry effects using ImageMagick
	// Try magick first (IMv7), fall back to convert (IMv6)

	// Get ImageMagick args from params
	var imagemagickArgs []string
	if cmd.Params != nil {
		if args, ok := cmd.Params["imagemagick_args"].([]interface{}); ok {
			imagemagickArgs = make([]string, len(args))
			for i, a := range args {
				imagemagickArgs[i] = fmt.Sprintf("%v", a)
			}
		}
	}
	if len(imagemagickArgs) == 0 {
		imagemagickArgs = []string{"-modulate", "100,200,100", "-contrast-stretch", "0", "-statistic", "NonPeak", "3", "-sharpen", "0x5"}
	}

	// Prepare args for convert (replace -statistic NonPeak 3 with -noise 3)
	convertArgs := make([]string, len(imagemagickArgs))
	copy(convertArgs, imagemagickArgs)
	for i := 0; i < len(convertArgs)-2; i++ {
		if convertArgs[i] == "-statistic" && convertArgs[i+1] == "NonPeak" && convertArgs[i+2] == "3" {
			convertArgs = append(convertArgs[:i], append([]string{"-noise", "3"}, convertArgs[i+3:]...)...)
			break
		}
	}

	var execCmd *exec.Cmd
	var stderr bytes.Buffer

	// Try different approaches to handle various image formats
	approaches := []func() *exec.Cmd{
		// Approach 1: Direct magick command
		func() *exec.Cmd {
			args := append([]string{inputPath}, imagemagickArgs...)
			args = append(args, outputFile.Name())
			return exec.Command("magick", args...)
		},
		// Approach 2: Force read as JPEG
		func() *exec.Cmd {
			args := append([]string{"JPEG:" + inputPath}, imagemagickArgs...)
			args = append(args, outputFile.Name())
			return exec.Command("magick", args...)
		},
		// Approach 3: Force read as PNG
		func() *exec.Cmd {
			args := append([]string{"PNG:" + inputPath}, imagemagickArgs...)
			args = append(args, outputFile.Name())
			return exec.Command("magick", args...)
		},
		// Approach 4: Old convert command
		func() *exec.Cmd {
			args := append([]string{inputPath}, convertArgs...)
			args = append(args, outputFile.Name())
			return exec.Command("convert", args...)
		},
	}

	var lastErr error
	var lastStderr string
	for _, approach := range approaches {
		execCmd = approach()
		stderr.Reset()
		execCmd.Stderr = &stderr

		if err := execCmd.Run(); err == nil {
			// Success!
			break
		} else {
			lastErr = err
			lastStderr = stderr.String()
			log.Debug().Err(err).Str("stderr", lastStderr).Msg("conversion approach failed, trying next")
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("failed to run ImageMagick with all approaches: %w, last stderr: %s", lastErr, lastStderr)
	}

	// Read the processed image
	processedData, err := os.ReadFile(outputFile.Name())
	if err != nil {
		return "", fmt.Errorf("failed to read processed image: %w", err)
	}

	// Upload the processed image
	uploadResp, err := matrixClient.UploadBytes(ctx, processedData, "image/jpeg")
	if err != nil {
		return "", fmt.Errorf("failed to upload processed image: %w", err)
	}

	// Send the processed image as a reply
	imageContent := event.MessageEventContent{
		MsgType:   event.MsgImage,
		Body:      "deepfried.jpg",
		URL:       uploadResp.ContentURI.CUString(),
		RelatesTo: &event.RelatesTo{InReplyTo: &event.InReplyTo{EventID: ev.ID}},
	}

	_, err = matrixClient.SendMessageEvent(ctx, ev.RoomID, event.EventMessage, &imageContent)
	if err != nil {
		return "", fmt.Errorf("failed to send processed image: %w", err)
	}

	return "Image deepfried! 🔥", nil
}

// handleQuackCommand fetches a random duck image from random-d.uk API
func handleQuackCommand(ctx context.Context, ev *event.Event, matrixClient *mautrix.Client, cmd *BotCommand) (string, error) {
	url := "https://random-d.uk/api/random" // default
	if cmd.Params != nil {
		if u, ok := cmd.Params["url"].(string); ok {
			url = u
		}
	}
	// Fetch random duck image URL from API
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "ash-bot (https://github.com/polarhive/ash)")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch duck API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("duck API returned status %d", resp.StatusCode)
	}

	// Parse JSON response
	var apiResp struct {
		Message string `json:"message"`
		URL     string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("failed to parse API response: %w", err)
	}

	if apiResp.URL == "" {
		return "", fmt.Errorf("no image URL in API response")
	}

	log.Info().Str("image_url", apiResp.URL).Msg("fetched duck image URL")

	// Download the image
	imageResp, err := http.Get(apiResp.URL)
	if err != nil {
		return "", fmt.Errorf("failed to download image: %w", err)
	}
	defer imageResp.Body.Close()

	if imageResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("image download failed with status %d", imageResp.StatusCode)
	}

	imageData, err := io.ReadAll(imageResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read image data: %w", err)
	}

	log.Info().Int("size", len(imageData)).Msg("downloaded duck image")

	// Determine content type
	contentType := imageResp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "image/jpeg" // default fallback
	}

	// Upload the image to Matrix
	uploadResp, err := matrixClient.UploadBytes(ctx, imageData, contentType)
	if err != nil {
		return "", fmt.Errorf("failed to upload image: %w", err)
	}

	// Send the image as a reply
	imageContent := event.MessageEventContent{
		MsgType:   event.MsgImage,
		Body:      "quack.jpg",
		URL:       uploadResp.ContentURI.CUString(),
		RelatesTo: &event.RelatesTo{InReplyTo: &event.InReplyTo{EventID: ev.ID}},
	}

	_, err = matrixClient.SendMessageEvent(ctx, ev.RoomID, event.EventMessage, &imageContent)
	if err != nil {
		return "", fmt.Errorf("failed to send image: %w", err)
	}

	return "🦆 Quack!", nil
}

// handleMeowCommand fetches a random cat image from The Cat API
func handleMeowCommand(ctx context.Context, ev *event.Event, matrixClient *mautrix.Client, cmd *BotCommand) (string, error) {
	url := "https://api.thecatapi.com/v1/images/search" // default
	if cmd.Params != nil {
		if u, ok := cmd.Params["url"].(string); ok {
			url = u
		}
	}
	// Fetch random cat image from The Cat API
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "ash-bot (https://github.com/polarhive/ash)")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch cat API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cat API returned status %d", resp.StatusCode)
	}

	// Parse JSON response - API returns an array of cat objects
	var apiResp []struct {
		ID     string `json:"id"`
		URL    string `json:"url"`
		Width  int    `json:"width"`
		Height int    `json:"height"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("failed to parse API response: %w", err)
	}

	if len(apiResp) == 0 || apiResp[0].URL == "" {
		return "", fmt.Errorf("no image URL in API response")
	}

	imageURL := apiResp[0].URL
	log.Info().Str("image_url", imageURL).Str("cat_id", apiResp[0].ID).Msg("fetched cat image")

	// Download the image
	imageResp, err := http.Get(imageURL)
	if err != nil {
		return "", fmt.Errorf("failed to download image: %w", err)
	}
	defer imageResp.Body.Close()

	if imageResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("image download failed with status %d", imageResp.StatusCode)
	}

	imageData, err := io.ReadAll(imageResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read image data: %w", err)
	}

	log.Info().Int("size", len(imageData)).Msg("downloaded cat image")

	// Determine content type
	contentType := imageResp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "image/jpeg" // default fallback
	}

	// Upload the image to Matrix
	uploadResp, err := matrixClient.UploadBytes(ctx, imageData, contentType)
	if err != nil {
		return "", fmt.Errorf("failed to upload image: %w", err)
	}

	// Send the image as a reply
	imageContent := event.MessageEventContent{
		MsgType:   event.MsgImage,
		Body:      "meow.jpg",
		URL:       uploadResp.ContentURI.CUString(),
		RelatesTo: &event.RelatesTo{InReplyTo: &event.InReplyTo{EventID: ev.ID}},
	}

	_, err = matrixClient.SendMessageEvent(ctx, ev.RoomID, event.EventMessage, &imageContent)
	if err != nil {
		return "", fmt.Errorf("failed to send image: %w", err)
	}

	return "🐱 Meow!", nil
}

// handleJokeCommand fetches a random joke from configured API
func handleJokeCommand(ctx context.Context, cmd *BotCommand) (string, error) {
	url := "https://icanhazdadjoke.com/" // default
	headers := map[string]string{"Accept": "application/json"}
	if cmd.Params != nil {
		if u, ok := cmd.Params["url"].(string); ok {
			url = u
		}
		if h, ok := cmd.Params["headers"].(map[string]interface{}); ok {
			for k, v := range h {
				if vs, ok := v.(string); ok {
					headers[k] = vs
				}
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "ash-bot (https://github.com/polarhive/ash)")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var payload struct {
		Joke string `json:"joke"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.Joke, nil
}
