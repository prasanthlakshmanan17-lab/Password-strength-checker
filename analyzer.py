"""Password Strength Analyzer & Secure Password Generator.

Passwords are analyzed in memory only. Nothing is stored, logged or uploaded.
"""
import getpass
import math
import re
import secrets
import string

# Small sample list of very common passwords (lowercase).
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
    "football", "login", "passw0rd", "master", "hello", "freedom",
    "whatever", "trustno1", "111111", "000000", "sunshine", "princess",
}

KEYBOARD_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz",
]

# Reverse leetspeak so "P@ssw0rd" is caught as "password".
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                          "0": "o", "$": "s", "5": "s", "7": "t"})


def has_repeated_chars(pw: str, run: int = 3) -> bool:
    """True if the same character appears `run` or more times in a row."""
    return re.search(r"(.)\1{%d,}" % (run - 1), pw) is not None


def has_repeated_pattern(pw: str) -> bool:
    """True for patterns like 'abcabc' or 'xyzxyzxyz'."""
    return re.fullmatch(r"(.{2,}?)\1+", pw) is not None


def has_sequence(pw: str, length: int = 4) -> bool:
    """True if pw has `length` consecutive chars from a keyboard/alphabet/number run."""
    low = pw.lower()
    for seq in KEYBOARD_SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - length + 1):
                if s[i:i + length] in low:
                    return True
    return False


def is_common(pw: str) -> bool:
    low = pw.lower()
    normalized = low.translate(LEET_MAP)
    stripped = re.sub(r"\d+$", "", normalized)  # password123 -> password
    return low in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS or stripped in COMMON_PASSWORDS


def entropy_bits(pw: str) -> float:
    """Estimate entropy = length * log2(character pool size)."""
    pool = 0
    if re.search(r"[a-z]", pw): pool += 26
    if re.search(r"[A-Z]", pw): pool += 26
    if re.search(r"\d", pw): pool += 10
    if re.search(r"[^A-Za-z0-9]", pw): pool += 32
    return len(pw) * math.log2(pool) if pool else 0.0


def analyze(pw: str) -> dict:
    """Return score (0-100), label (Weak/Medium/Strong), issues and recommendations."""
    issues, tips = [], []
    score = 0

    # --- Rule 1: length ---
    n = len(pw)
    if n < 8:
        issues.append("Too short (under 8 characters)")
        tips.append("Use at least 12 characters.")
    elif n < 12:
        score += 15
        tips.append("Increase length to 12+ characters.")
    elif n < 16:
        score += 25
    else:
        score += 30

    # --- Rule 2: character variety ---
    checks = [
        (r"[a-z]", "lowercase letters"),
        (r"[A-Z]", "uppercase letters"),
        (r"\d", "numbers"),
        (r"[^A-Za-z0-9]", "special symbols (!@#$...)"),
    ]
    kinds = 0
    for pattern, name in checks:
        if re.search(pattern, pw):
            kinds += 1
        else:
            issues.append(f"Missing {name}")
            tips.append(f"Add {name}.")
    score += kinds * 10  # up to 40

    # --- Rule 3: weak patterns (penalties) ---
    if has_repeated_chars(pw):
        issues.append("Repeated characters (e.g. 'aaa')")
        tips.append("Avoid repeating the same character 3+ times.")
        score -= 15
    if has_repeated_pattern(pw):
        issues.append("Repeated pattern (e.g. 'abcabc')")
        tips.append("Avoid repeating a block of characters.")
        score -= 15
    if has_sequence(pw):
        issues.append("Sequential/keyboard pattern (e.g. '1234', 'qwerty')")
        tips.append("Avoid sequences like 1234, abcd or qwerty.")
        score -= 30
    common = is_common(pw)
    if common:
        issues.append("Common/guessable password")
        tips.append("Never use common passwords or simple variations of them.")
        score -= 40

    # --- Rule 4: entropy bonus ---
    bits = entropy_bits(pw)
    if bits >= 60: score += 30
    elif bits >= 40: score += 15

    score = max(0, min(100, score))

    # Hard rules: short/common -> Weak; Strong also needs 12+ characters.
    if n < 8 or common:
        label = "Weak"
    elif score >= 75 and n >= 12:
        label = "Strong"
    elif score >= 50:
        label = "Medium"
    else:
        label = "Weak"

    return {"score": score, "label": label, "entropy": round(bits, 1),
            "issues": issues, "recommendations": tips}


def generate_password(length=16, upper=True, lower=True, digits=True, symbols=True) -> str:
    """Generate a password with the `secrets` module (cryptographically secure)."""
    pools = []
    if lower: pools.append(string.ascii_lowercase)
    if upper: pools.append(string.ascii_uppercase)
    if digits: pools.append(string.digits)
    if symbols: pools.append("!@#$%^&*()-_=+[]{};:,.?")
    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError("Length too short for the selected character types.")

    # Guarantee at least one char from each selected pool, then fill the rest.
    chars = [secrets.choice(p) for p in pools]
    all_chars = "".join(pools)
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def print_report(pw: str) -> None:
    r = analyze(pw)
    print(f"\nStrength : {r['label']}  (score {r['score']}/100, ~{r['entropy']} bits entropy)")
    if r["issues"]:
        print("Issues:")
        for i in r["issues"]:
            print(f"  - {i}")
    if r["recommendations"] and r["label"] != "Strong":
        print("Recommendations:")
        for t in r["recommendations"]:
            print(f"  * {t}")
    if r["label"] == "Strong":
        print("Great password! Keep it unique for every account.")


def ask_yes(prompt: str, default=True) -> bool:
    ans = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not ans else ans.startswith("y")


def menu() -> None:
    print("=" * 50)
    print(" Password Strength Analyzer & Generator")
    print(" (passwords are never stored or uploaded)")
    print("=" * 50)
    while True:
        print("\n1. Analyze a password\n2. Generate a secure password\n3. Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            pw = getpass.getpass("Enter password (hidden): ")
            if pw:
                print_report(pw)
            else:
                print("Empty password.")
        elif choice == "2":
            try:
                length = int(input("Length (default 16): ") or 16)
                pw = generate_password(
                    length,
                    upper=ask_yes("Uppercase?"), lower=ask_yes("Lowercase?"),
                    digits=ask_yes("Numbers?"), symbols=ask_yes("Symbols?"),
                )
                print(f"\nGenerated: {pw}")
                print_report(pw)
            except ValueError as e:
                print(f"Error: {e}")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    menu()
