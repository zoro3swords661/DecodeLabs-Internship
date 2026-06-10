# Password Strength Checker

A simple desktop app that checks how strong your password is. Built with Python and Tkinter as part of my cybersecurity internship at DecodeLabs.

---

## What it does

You type in a password and it tells you if it's **WEAK**, **MEDIUM**, or **STRONG** based on:

- password length (8+ and 12+ characters)
- uppercase letters (A-Z)
- lowercase letters (a-z)
- numbers (0-9)
- special symbols like `! @ # $`

It also gives tips on what to improve and shows a color bar so you can see the strength at a glance.

---

## Screenshot

> red = weak, orange = medium, green = strong

![app preview](screenshot.png)

*(add a screenshot of your app here)*

---

## How to run

Make sure you have Python installed (3.x). Tkinter comes with Python so no extra installs needed.

```bash
python password_checker_ui.py
```

That's it.

---

## How scoring works

Each condition gives 1 point. Max score is 6.

| Condition | Points |
|---|---|
| 8 or more characters | 1 |
| 12 or more characters | 1 |
| Has uppercase letter | 1 |
| Has lowercase letter | 1 |
| Has a number | 1 |
| Has a symbol | 1 |

- score 0-2 = WEAK
- score 3-4 = MEDIUM
- score 5-6 = STRONG

---

## Files

```
password_checker_ui.py   - main file, run this
README.md                - this file
```

---

## What I learned

- string handling in Python (looping through characters)
- how to use if/elif conditions for logic
- basics of what makes a password secure
- building a simple GUI with tkinter

---

## Internship

This is Project 1 of my Cyber Security internship at **DecodeLabs** (Batch 2026).

The goal of this project was to understand the basics of data validation and security logic before moving on to more advanced topics like hashing and encryption in Project 2.
