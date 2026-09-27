// Package openlitespeed reads OpenLiteSpeed configuration: the server-level
// httpd_config.conf (virtualHost and listener blocks) and per-vhost
// vhost.conf files. It never writes configuration.
package openlitespeed

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// Node is one directive or block in an OLS config file.
type Node struct {
	Key   string  // directive or block keyword, e.g. "docRoot", "virtualHost"
	Value string  // rest of the line (block name for blocks)
	Kids  []*Node // children for blocks
	Line  int
	Block bool
}

// Find returns the first direct child with key (case-insensitive).
func (n *Node) Find(key string) *Node {
	for _, k := range n.Kids {
		if strings.EqualFold(k.Key, key) {
			return k
		}
	}
	return nil
}

// All returns every direct child with key.
func (n *Node) All(key string) []*Node {
	var out []*Node
	for _, k := range n.Kids {
		if strings.EqualFold(k.Key, key) {
			out = append(out, k)
		}
	}
	return out
}

// Get returns the value of the first child directive key, or "".
func (n *Node) Get(key string) string {
	if k := n.Find(key); k != nil {
		return k.Value
	}
	return ""
}

// ParseError describes a structural problem, with a 1-based line number.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// Parse reads an OLS config. It understands blocks ("name value {" ... "}"),
// single-line directives, comments and <<<END_x heredocs.
func Parse(b []byte) (*Node, error) {
	root := &Node{Key: "root", Block: true}
	stack := []*Node{root}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	ln := 0
	heredoc := ""
	var hd *Node
	for sc.Scan() {
		ln++
		raw := sc.Text()
		if heredoc != "" {
			if strings.TrimSpace(raw) == heredoc {
				heredoc, hd = "", nil
				continue
			}
			hd.Value += raw + "\n"
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cur := stack[len(stack)-1]
		if line == "}" {
			if len(stack) == 1 {
				return nil, &ParseError{ln, "unexpected '}'"}
			}
			stack = stack[:len(stack)-1]
			continue
		}
		key, val := splitKV(line)
		if strings.HasSuffix(line, "{") {
			val = strings.TrimSpace(strings.TrimSuffix(val, "{"))
			if key == "{" || key == "" {
				return nil, &ParseError{ln, "block without a name"}
			}
			key = strings.TrimSuffix(key, "{")
			n := &Node{Key: key, Value: val, Line: ln, Block: true}
			cur.Kids = append(cur.Kids, n)
			stack = append(stack, n)
			continue
		}
		if strings.ContainsAny(stripBraceSafe(line), "{}") {
			return nil, &ParseError{ln, fmt.Sprintf("stray brace in %q", key)}
		}
		n := &Node{Key: key, Value: val, Line: ln}
		if i := strings.Index(val, "<<<"); i >= 0 {
			heredoc = strings.TrimSpace(val[i+3:])
			n.Value = ""
			hd = n
		}
		cur.Kids = append(cur.Kids, n)
	}
	if heredoc != "" {
		return nil, &ParseError{ln, "unterminated heredoc " + heredoc}
	}
	if len(stack) != 1 {
		open := stack[len(stack)-1]
		return nil, &ParseError{open.Line, fmt.Sprintf("block %q is never closed", open.Key)}
	}
	return root, sc.Err()
}

func splitKV(line string) (string, string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(line[i+1:])
}

// expand substitutes OLS variables.
func expand(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "$"+k, v)
	}
	return s
}

// stripBraceSafe removes quoted strings and %{...} log-format tokens, where
// braces are legitimate, before the stray-brace check.
func stripBraceSafe(line string) string {
	var b strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case inQ:
		case c == '%' && i+1 < len(line) && line[i+1] == '{':
			if j := strings.IndexByte(line[i:], '}'); j > 0 {
				i += j
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
