import re
import shlex

"""
EXAMPLE CODE BLOCK INPUT:
    certipy find -p password -u 'user' -ip 10.0.0.0 -d domain -target target.com

EXPECTED CODE BLOCK OUTPUT:
    certipy find -d 'domain' -ip '10.0.0.0' \
                 -p 'password' -target 'target.com' \
                 -u 'user'
"""

# Flag order
custom_order = ["-k", "-u", "-p", "-d", "-dc-ip", "-ns", "-target", "-target-ip", "-ca", "-config", "-backup", "-add-officer", "-enable-template", "-issue-request", "-retrieve", "-template", "-ca-pfx", "-pfx", "-username", "-domain", "-ldap-shell", "-upn", "-dns", "-sid", "-on-behalf-of", "-crl", "-application-policies", "-user", "-account", "-text", "-enabled", "-hide-admins", "-save-configuration", "-write-default-configuration", "-write-configuration", "-device-id", "-no-save", "read", "update", "auto", "add", "remove"]

def quote_argument(arg):
    if arg.startswith("'") and arg.endswith("'"):
        return arg
    return f"'{arg}'"

def get_flag_sort_key(flag_tuple):
    flag = flag_tuple[0]
    try:
        return (0, custom_order.index(flag))
    except ValueError:
        print(f"Warning: Flag '{flag}' not in custom order. Defaulting to end of list.")
        return (1, flag)

def format_certipy_command(line: str, indent: str, max_flags_per_line=2) -> str:
    try:
        tokens = shlex.split(line.strip())
    except ValueError:
        # fallback for malformed lines
        return indent + line.strip()

    if not tokens or tokens[0] != "certipy" or len(tokens) < 2:
        return indent + line.strip()
    
    # Skip short lines
    if len(indent + line.strip()) <= 80:
        print(f"Skipping short line: {line.strip()}")
        return indent + line.strip()

    base_command = tokens[:2]
    args = tokens[2:]

    grouped_args = []
    i = 0
    while i < len(args):
        if args[i].startswith("-"):
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                grouped_args.append((args[i], quote_argument(args[i + 1])))
                i += 2
            else:
                grouped_args.append((args[i],))
                i += 1
        else:
            grouped_args.append((args[i],))
            i += 1

    grouped_args.sort(key=get_flag_sort_key)

    result = []

    # Add first line: certipy subcommand \
    first_line = indent + " ".join(base_command)
    if grouped_args:
        first_line += " \\"
    result.append(first_line)

    # Add subsequent flag lines
    for j in range(0, len(grouped_args), max_flags_per_line):
        parts = grouped_args[j:j + max_flags_per_line]
        line = indent + " " * 4 + " ".join(" ".join(part) for part in parts)
        if j + max_flags_per_line < len(grouped_args):
            line += " \\"
        result.append(line)

    return "\n".join(result)

def process_markdown(input_path: str, output_path: str):
    with open(input_path, "r") as f:
        lines = f.readlines()

    in_bash_block = False
    result = []

    for line in lines:
        if line.strip().startswith("```bash"):
            in_bash_block = True
            result.append(line)
            continue
        elif line.strip().startswith("```") and in_bash_block:
            in_bash_block = False
            result.append(line)
            continue

        if in_bash_block and "certipy" in line.strip():
            indent = re.match(r'^(\s*)', line).group(1)
            result.append(format_certipy_command(line, indent) + "\n")
        else:
            result.append(line)

    with open(output_path, "w") as f:
        f.writelines(result)

# Example usage:
process_markdown("07-‐-Post‐Exploitation.md", "output.md")
