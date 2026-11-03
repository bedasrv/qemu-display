"""Delimiter-balance oracle for Rust source, tolerant of comments, strings and lifetimes.

Used to reject an edit that splices code together: a splice almost always
leaves the delimiter count non-zero or changed.
"""
def strip(src):
    """Remove comments, string and char literal bodies so delimiters inside them
    are not counted. Returns the source with those regions blanked."""
    out = []
    i, n = 0, len(src)
    depth_block = 0
    while i < n:
        c = src[i]
        # block comment, nestable in Rust
        if depth_block:
            if src.startswith('/*', i):
                depth_block += 1; out.append('  '); i += 2; continue
            if src.startswith('*/', i):
                depth_block -= 1; out.append('  '); i += 2; continue
            out.append('\n' if c == '\n' else ' '); i += 1; continue
        if src.startswith('/*', i):
            depth_block = 1; out.append('  '); i += 2; continue
        # line comment
        if src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i)); i = j; continue
        # raw string: r"..." r#"..."# r##"..."##
        if c == 'r' and i + 1 < n and (src[i + 1] in '"#'):
            j = i + 1
            hashes = 0
            while j < n and src[j] == '#':
                hashes += 1; j += 1
            if j < n and src[j] == '"':
                term = '"' + '#' * hashes
                k = src.find(term, j + 1)
                k = n if k < 0 else k + len(term)
                out.append(' ' * (k - i)); i = k; continue
        # byte string / c string prefixes
        if c in 'bc' and i + 1 < n and src[i + 1] in '"' and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_')):
            j = i + 1
            k = j + 1
            while k < n and src[k] != '"':
                k += 2 if src[k] == '\\' else 1
            k = min(k + 1, n)
            out.append(' ' * (k - i)); i = k; continue
        # normal string
        if c == '"':
            k = i + 1
            while k < n:
                if src[k] == '\\':
                    k += 2; continue
                if src[k] == '"':
                    k += 1; break
                k += 1
            out.append(' ' * (k - i)); i = k; continue
        # char literal, but not a lifetime: 'x' '\n' '\u{1}'
        if c == "'":
            k = i + 1
            if k < n and src[k] == '\\':
                k += 2
                while k < n and src[k] != "'":
                    k += 1
                k += 1
            elif k + 1 < n and src[k + 1] == "'":
                k += 2
            else:
                out.append(c); i += 1; continue      # a lifetime: leave it alone
            out.append(' ' * min(k - i, n - i)); i = k; continue
        out.append(c); i += 1
    return ''.join(out)


def balance(src):
    """(depth, first_unbalanced) for () [] {}. depth 0 means balanced."""
    s = strip(src)
    stack = []
    pairs = {')': '(', ']': '[', '}': '{'}
    line = 1
    for ch in s:
        if ch == '\n':
            line += 1
        elif ch in '([{':
            stack.append((ch, line))
        elif ch in ')]}':
            if not stack or stack[-1][0] != pairs[ch]:
                return len(stack) + 1, line
            stack.pop()
    return len(stack), (stack[-1][1] if stack else None)


def unbalanced(src):
    return balance(src)[0] != 0