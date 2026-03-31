package service

import (
	"context"
	"strings"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

// ListFolders lists all available mailboxes from the IMAP server and builds a tree structure.
func ListFolders(ctx context.Context, ep models.MigrationEndpoint) (*models.ListFoldersResponse, error) {
	c, err := Connect(ctx, ep)
	if err != nil {
		return nil, err
	}
	defer c.Logout()

	mailboxes := make(chan *imap.MailboxInfo, 20)
	done := make(chan error, 1)
	go func() {
		done <- c.List("", "*", mailboxes)
	}()

	var rawNodes []*models.FolderNode
	for mb := range mailboxes {
		name := mb.Name
		delim := mb.Delimiter

		// Skip GMAIL virtual folders that cause duplicate
		if IsGmailVirtualFolder(name) {
			continue
		}

		rawNodes = append(rawNodes, &models.FolderNode{
			Name:      name, // Will be updated to basename in buildTree
			FullPath:  name,
			Delimiter: delim,
			Children:  []*models.FolderNode{},
		})
	}

	if err := <-done; err != nil {
		return nil, FriendlyError(err)
	}

	tree := buildTree(rawNodes)

	return &models.ListFoldersResponse{
		Folders: tree,
	}, nil
}

// buildTree converts a flat list of folders into a hierarchical tree based on their delimiters
func buildTree(nodes []*models.FolderNode) []*models.FolderNode {
	var roots []*models.FolderNode
	nodeMap := make(map[string]*models.FolderNode)

	// Sort nodes by path length to ensure parents are processed before children
	// A simpler approach is just to map them all, then link
	for _, n := range nodes {
		nodeMap[n.FullPath] = n
	}

	for _, n := range nodes {
		if n.Delimiter == "" {
			n.Name = n.FullPath
			roots = append(roots, n)
			continue
		}

		parts := strings.Split(n.FullPath, n.Delimiter)
		n.Name = parts[len(parts)-1]

		if len(parts) == 1 {
			roots = append(roots, n)
		} else {
			// Find parent
			parentPath := strings.Join(parts[:len(parts)-1], n.Delimiter)
			if parent, ok := nodeMap[parentPath]; ok {
				parent.Children = append(parent.Children, n)
			} else {
				// Parent doesn't exist in the list (e.g. skipped or server didn't return it)
				// Attach as root
				roots = append(roots, n)
			}
		}
	}

	return roots
}

// IsGmailVirtualFolder checks if a folder is a known Gmail virtual folder
// that should be skipped to prevent email duplication.
func IsGmailVirtualFolder(folderName string) bool {
	lower := strings.ToLower(folderName)
	return strings.Contains(lower, "[gmail]/all mail") ||
		strings.Contains(lower, "[gmail]/important") ||
		strings.Contains(lower, "[gmail]/starred")
}

// CanonicalizeSelection takes a list of selected folder paths and returns an optimized list.
// If a parent folder is selected, all its descendants are removed from the selection list,
// as the migration logic will recursively migrate the parent and all its children.
func CanonicalizeSelection(folders []string, delimiter string) []string {
	if len(folders) == 0 {
		return []string{}
	}

	selectedMap := make(map[string]bool)
	for _, f := range folders {
		selectedMap[f] = true
	}

	var optimized []string
	for _, f := range folders {
		isChildOfSelectedParent := false
		
		// If delimiter is empty, we can't determine hierarchy reliably, treat all as flat.
		if delimiter != "" {
			parts := strings.Split(f, delimiter)
			// Check all possible parent paths
			// path: A/B/C -> check A, A/B
			for i := 1; i < len(parts); i++ {
				parentPath := strings.Join(parts[:i], delimiter)
				if selectedMap[parentPath] {
					isChildOfSelectedParent = true
					break
				}
			}
		}

		if !isChildOfSelectedParent {
			optimized = append(optimized, f)
		}
	}

	return optimized
}

// ExpandRecursive takes canonicalized folders and expands them back into flat lists
// of all mailboxes to actually migrate (because go-imap needs exact mailbox names to Select).
// It queries the IMAP server to find all existing descendants.
func ExpandRecursive(ctx context.Context, c *client.Client, selectedPaths []string) ([]string, error) {
	mailboxesChan := make(chan *imap.MailboxInfo, 20)
	done := make(chan error, 1)
	go func() {
		done <- c.List("", "*", mailboxesChan)
	}()

	// Build a fast lookup for all available server paths
	availableMap := make(map[string]string)
	for mb := range mailboxesChan {
		if !IsGmailVirtualFolder(mb.Name) {
			availableMap[mb.Name] = mb.Delimiter
		}
	}
	if err := <-done; err != nil {
		return nil, FriendlyError(err)
	}

	var flatFinal []string
	finalMap := make(map[string]bool)

	for _, sel := range selectedPaths {
		// If exactly selected exists:
		if _, ok := availableMap[sel]; ok {
			if !finalMap[sel] {
				flatFinal = append(flatFinal, sel)
				finalMap[sel] = true
			}
		}

		// Also find all descendants
		for availPath, delim := range availableMap {
			if delim != "" {
				prefix := sel + delim
				if strings.HasPrefix(availPath, prefix) {
					if !finalMap[availPath] {
						flatFinal = append(flatFinal, availPath)
						finalMap[availPath] = true
					}
				}
			}
		}
	}

	return flatFinal, nil
}
