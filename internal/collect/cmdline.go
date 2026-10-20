package collect

import (
	"path"
	"regexp"
	"strings"
)

type token struct {
	text string
	kind byte // 'w' word, 's' separator (; && || | & ( ) { }), 'r' redirection
}

// shellTokens splits a command line roughly the way sh does: words with
// quotes removed, separators and redirections as their own tokens. A
// redirection's target is attached when written together (2>&1, >/dev/null);
// otherwise it is the next token.
func shellTokens(s string) []token {
	var out []token
	var cur strings.Builder
	inWord := false
	emit := func() {
		if inWord {
			out = append(out, token{text: cur.String(), kind: 'w'})
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				j = len(s) - i - 1
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == '\\' && i+1 < len(s):
			inWord = true
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t' || c == '\n':
			emit()
		case strings.IndexByte(";&|(){}", c) >= 0 && !(c == '&' && i+1 < len(s) && s[i+1] == '>'):
			emit()
			op := string(c)
			if i+1 < len(s) && (c == '&' || c == '|') && s[i+1] == c {
				op += string(c)
				i++
			}
			out = append(out, token{text: op, kind: 's'})
		case c == '>' || c == '<' || (c == '&' && i+1 < len(s) && s[i+1] == '>'):
			// A digit right before it belongs to the redirection (2>).
			if inWord && isDigits(cur.String()) {
				cur.Reset()
				inWord = false
			}
			emit()
			j := i
			for j < len(s) && strings.IndexByte("<>&", s[j]) >= 0 {
				j++
			}
			k := j
			for k < len(s) && strings.IndexByte(" \t;|()", s[k]) < 0 {
				k++
			}
			out = append(out, token{text: s[i:k], kind: 'r'})
			i = k - 1
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	emit()
	return out
}

func isAssignment(w string) bool {
	i := strings.IndexByte(w, '=')
	return i > 0 && envName.MatchString(w[:i])
}

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// Programs whose script argument root runs too, and the shells among them.
var (
	interpreter = regexp.MustCompile(`^(sh|bash|dash|ash|ksh|zsh|python[0-9.]*|perl[0-9.]*|php[0-9.]*|ruby[0-9.]*|node|nodejs|lua[0-9.]*|tclsh[0-9.]*)$`)
	shellName   = regexp.MustCompile(`^(sh|bash|dash|ash|ksh|zsh)$`)
)

// Wrappers run the command that follows them.
var wrapper = map[string]bool{
	"nice": true, "ionice": true, "nohup": true, "env": true, "timeout": true, "flock": true,
	"chronic": true, "run-one": true, "setsid": true, "stdbuf": true, "exec": true, "time": true,
	"command": true, "xargs": true, "systemd-cat": true,
}

// Programs after which the rest runs as someone else (or not at all as
// root), so it is no root route.
var switchUser = map[string]bool{"sudo": true, "su": true, "runuser": true, "setpriv": true, "chroot": true, "doas": true}

// Shell keywords that keep the next word in command position.
var keyword = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "fi": true, "do": true, "done": true, "while": true, "until": true, "!": true}

// wrapperArg matches option values a wrapper takes, which are not the
// command: numbers, durations, signal names.
var wrapperArg = regexp.MustCompile(`^([0-9.]+[smhd]?|[A-Z]+[0-9]*)$`)

// CommandPaths returns the files a shell command line runs: every program
// given with a path, the script given to an interpreter, and what `sh -c`
// runs. Programs found through PATH are left out (the PATH directories are
// checked instead), and so are redirection targets and arguments.
// unquoted says the line lost its quoting (systemctl prints argv joined
// with spaces), so `sh -c` runs everything after it.
func CommandPaths(line string, unquoted bool) []string {
	return commandPaths(shellTokens(line), unquoted, 0)
}

func commandPaths(toks []token, unquoted bool, depth int) []string {
	var out []string
	cmdPos, afterWrapper, script, shell := true, "", false, false
	cwd := ""
	resolve := func(w string) string {
		switch {
		case strings.HasPrefix(w, "/"):
			return path.Clean(w)
		case cwd != "" && (strings.HasPrefix(w, "./") || strings.HasPrefix(w, "../")):
			return path.Join(cwd, w)
		}
		return ""
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case 's':
			cmdPos, afterWrapper, script, shell = true, "", false, false
			continue
		case 'r':
			if strings.Trim(t.text, "<>&") == "" { // target is the next word
				i++
			}
			continue
		}
		w := t.text
		switch {
		case cmdPos && keyword[w]:
			continue
		case cmdPos && afterWrapper != "":
			if strings.HasPrefix(w, "-") || strings.Contains(w, "=") || wrapperArg.MatchString(w) {
				continue
			}
			if afterWrapper == "flock" { // flock [options] lockfile command
				afterWrapper = "flock-file"
				continue
			}
		case cmdPos && isAssignment(w):
			continue // VAR=value before the command
		}
		if cmdPos {
			base := path.Base(w)
			if switchUser[base] {
				cmdPos, script = false, false
				// Skip to the next separator: what follows runs as another user.
				for i+1 < len(toks) && toks[i+1].kind != 's' {
					i++
				}
				continue
			}
			if p := resolve(w); p != "" {
				out = append(out, p)
			}
			if base == "cd" && i+1 < len(toks) && toks[i+1].kind == 'w' && strings.HasPrefix(toks[i+1].text, "/") {
				cwd = path.Clean(toks[i+1].text)
				i++
				cmdPos = false
				continue
			}
			if wrapper[base] {
				afterWrapper = base
				continue
			}
			cmdPos, afterWrapper = false, ""
			script = interpreter.MatchString(base)
			shell = shellName.MatchString(base)
			continue
		}
		if !script {
			continue
		}
		if shell && w == "-c" && depth < 3 {
			var sub []token
			switch {
			case unquoted:
				for i+1 < len(toks) && toks[i+1].kind != 's' {
					i++
					sub = append(sub, toks[i])
				}
				sub = shellTokens(joinTokens(sub))
			case i+1 < len(toks):
				i++
				sub = shellTokens(toks[i].text)
			}
			out = append(out, commandPaths(sub, unquoted, depth+1)...)
			script = false
			continue
		}
		if strings.HasPrefix(w, "-") {
			continue // interpreter options
		}
		if p := resolve(w); p != "" {
			out = append(out, p)
		}
		script = false
	}
	return out
}

func joinTokens(toks []token) string {
	parts := make([]string, len(toks))
	for i, t := range toks {
		parts[i] = t.text
	}
	return strings.Join(parts, " ")
}
