# Password Strength Analyzer & Secure Password Generator

A Python command-line cybersecurity tool that analyzes password strength, gives recommendations, and generates secure passwords.

> **Privacy:** Passwords are processed only in memory. They are never stored, logged, or uploaded. Input is hidden using `getpass`.

## Features
- Strength result: **Weak / Medium / Strong** with a score out of 100
- Entropy estimate (in bits)
- Detects weak patterns: short length, repeated characters, repeated blocks, sequences (`1234`, `qwerty`), common passwords (incl. leetspeak like `P@ssw0rd`)
- Improvement recommendations for weak passwords
- Secure password generator with user-selected length and character types (uses Python's `secrets` module)

## Setup
Requires Python 3.8+. No external libraries needed.

```bash
git clone <your-repo-url>
cd password-strength-analyzer
python analyzer.py
```

Run tests:
```bash
python tests/test_analyzer.py
```

## Security Logic
| Rule | Effect |
|---|---|
| Length | <8 = Weak; 8-11 = +15; 12-15 = +25; 16+ = +30 |
| Variety (lower, upper, digit, symbol) | +10 each (max 40) |
| Repeated characters (`aaa`) | -15 |
| Repeated block (`abcabc`) | -15 |
| Sequence (`1234`, `qwerty`) | -30 |
| Common password / variation | -40 and forced Weak |
| Entropy `length x log2(pool size)` | >=40 bits +15; >=60 bits +30 |

**Final label:** score >= 75 and length >= 12 = **Strong**; score >= 50 = **Medium**; otherwise **Weak**.

**Generator:** uses `secrets` (cryptographically secure randomness), guarantees at least one character from every selected type, then shuffles.

## Sample Test Results
| Password (test example) | Result |
|---|---|
| `abc` | Weak |
| `password` | Weak |
| `P@ssw0rd` | Weak |
| `qwerty123456` | Weak |
| `Hello2024` | Medium |
| `Tr33House#9` | Medium |
| `k9$Lm2@xQ7!vRt4Z` | Strong |

## Project Structure
```
analyzer.py          # analysis + generator + CLI menu
tests/test_analyzer.py
README.md
```

## Author
Prasanth - Cyber Security Engineering, SRM Madurai College for Engineering and Technology
