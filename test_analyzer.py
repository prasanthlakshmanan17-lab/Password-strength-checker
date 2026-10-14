import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer import analyze, generate_password

# (password, expected label) - sample test passwords, not real ones
CASES = [
    ("abc", "Weak"),
    ("password", "Weak"),
    ("P@ssw0rd", "Weak"),
    ("aaaaaaaaaaaa", "Weak"),
    ("qwerty123456", "Weak"),
    ("abcabcabcabc", "Weak"),
    ("Hello2024", "Medium"),
    ("Tr33House#9", "Medium"),
    ("k9$Lm2@xQ7!vRt4Z", "Strong"),
    ("Blue-Horse-Battery-Staple-42!", "Strong"),
]


def test_labels():
    for pw, expected in CASES:
        got = analyze(pw)["label"]
        assert got == expected, f"{pw!r}: expected {expected}, got {got}"


def test_generator():
    for _ in range(100):
        pw = generate_password(16)
        assert len(pw) == 16
        assert analyze(pw)["label"] == "Strong"
    assert not any(c.isdigit() for c in generate_password(20, digits=False))


if __name__ == "__main__":
    for pw, exp in CASES:
        r = analyze(pw)
        print(f"{pw:32} -> {r['label']:7} (expected {exp}) score={r['score']}")
    test_labels(); test_generator()
    print("\nAll tests passed.")
