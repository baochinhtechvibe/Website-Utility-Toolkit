package service

import (
	"context"
	"strings"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// MailboxInfo holds core data about an IMAP mailbox
type MailboxInfo struct {
	Name       string
	Delimiter  string
	Attributes []string
}

// FetchServerMailboxes lists all mailboxes from an IMAP server and extracts their properties.
func FetchServerMailboxes(ctx context.Context, c *client.Client) ([]MailboxInfo, error) {
	mailboxes := make(chan *imap.MailboxInfo, 50)
	done := make(chan error, 1)

	go func() {
		done <- c.List("", "*", mailboxes)
	}()

	var mboxes []MailboxInfo
	for m := range mailboxes {
		if IsGmailVirtualFolder(m.Name) {
			continue
		}
		mboxes = append(mboxes, MailboxInfo{
			Name:       m.Name,
			Delimiter:  m.Delimiter,
			Attributes: m.Attributes,
		})
	}

	if err := <-done; err != nil {
		return nil, FriendlyError(err)
	}

	return mboxes, nil
}

// BuildFolderMap creates a mapping from source folder paths to destination folder paths.
//
// Strategy:
//  1. Build a lookup of dest special-use folders (RFC 6154 flags like \Sent, \Trash, etc.)
//  2. For each source folder:
//     a. Strip common namespace prefix (INBOX. from Courier/cPanel)
//     b. Translate delimiter (e.g. "." -> "/")
//     c. Match against well-known folder names (NOT source flags, which are unreliable from old servers)
//     d. Look up the correct dest folder by dest's special-use flag
//
// This avoids trusting source server attributes (which are often wrong on Courier/cPanel).
func BuildFolderMap(sourceMboxes, destMboxes []MailboxInfo) map[string]string {
	folderMap := make(map[string]string)

	// Determine dest delimiter and build special-use map from DESTINATION
	var destDelimiter string = "/"
	// destSpecialMap: RFC6154 flag (lowercase, e.g. "\\sent") -> dest folder name
	destSpecialMap := make(map[string]string)

	// Whitelist of real RFC 6154 special-use flags (avoids matching \Noselect, \HasChildren etc.)
	rfc6154Flags := map[string]bool{
		"\\sent":    true,
		"\\trash":   true,
		"\\drafts":  true,
		"\\junk":    true,
		"\\archive": true,
		"\\all":     true,
		"\\flagged": true,
		"\\inbox":   true,
	}

	for _, dm := range destMboxes {
		if dm.Delimiter != "" {
			destDelimiter = dm.Delimiter
		}
		for _, attr := range dm.Attributes {
			lowerAttr := strings.ToLower(attr)
			if rfc6154Flags[lowerAttr] {
				// Only register first occurrence per flag
				if _, exists := destSpecialMap[lowerAttr]; !exists {
					destSpecialMap[lowerAttr] = dm.Name
				}
			}
		}
	}

	// Determine source delimiter from first mailbox
	var srcDelimiter string = "."
	for _, sm := range sourceMboxes {
		if sm.Delimiter != "" {
			srcDelimiter = sm.Delimiter
			break
		}
	}

	for _, sm := range sourceMboxes {
		folderMap[sm.Name] = resolveDstFolder(sm.Name, srcDelimiter, destDelimiter, destSpecialMap)
	}

	return folderMap
}

// resolveDstFolder translates a single source folder name into the correct destination folder name.
// It does NOT trust source special-use attributes. Instead, it:
//  1. Strips namespace prefix (e.g. "INBOX.")
//  2. Translates delimiter
//  3. Matches by well-known folder name patterns
//  4. Looks up the correct dest folder via dest's own special-use flags
func resolveDstFolder(srcName, srcDelimiter, destDelimiter string, destSpecialMap map[string]string) string {
	// Special case: INBOX root always stays as INBOX
	if strings.EqualFold(srcName, "INBOX") {
		return "INBOX"
	}

	name := srcName

	// Step 1: Strip INBOX.<delimiter> prefix (Courier/cPanel namespace)
	lowerName := strings.ToLower(name)
	if srcDelimiter != "" {
		inboxPrefix := "inbox" + strings.ToLower(srcDelimiter)
		if strings.HasPrefix(lowerName, inboxPrefix) {
			name = name[len(inboxPrefix):]
		}
	}
	lowerName = strings.ToLower(name)

	// Step 2: Check if this is a well-known special folder (by name, not source flags)
	// Map name -> RFC 6154 flag to look up in destSpecialMap
	var specialFlag string
	var canonicalName string // English fallback if dest has no flag
	switch lowerName {
	case "sent", "sent items", "sent messages", "đã gửi", "sent-mail", "sentmail":
		specialFlag = "\\sent"
		canonicalName = "Sent"
	case "trash", "deleted", "deleted items", "deleted messages", "bin", "thùng rác":
		specialFlag = "\\trash"
		canonicalName = "Trash"
	case "drafts", "draft", "thư nháp":
		specialFlag = "\\drafts"
		canonicalName = "Drafts"
	case "spam", "junk", "junk email", "junk mail", "thư rác", "spambox":
		specialFlag = "\\junk"
		canonicalName = "Spam"
	case "archive", "archives":
		specialFlag = "\\archive"
		canonicalName = "Archive"
	}

	if specialFlag != "" {
		// Try to use destination's own folder that carries this flag
		if destName, ok := destSpecialMap[specialFlag]; ok {
			return destName
		}
		// Fall back to English canonical name
		return canonicalName
	}

	// Step 3: Not a special folder. Translate delimiter for custom/user-created folders.
	// e.g. Work.Project (Courier ".") -> Work/Project (Dovecot "/")
	if srcDelimiter != "" && destDelimiter != "" && srcDelimiter != destDelimiter {
		name = strings.ReplaceAll(name, srcDelimiter, destDelimiter)
	}

	return name
}
