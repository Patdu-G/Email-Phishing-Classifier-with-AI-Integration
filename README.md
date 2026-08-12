# Phish Classifier

A Python project for detecting phishing emails by analyzing `.eml` files.

## What it does so far
- Parses email subject, sender, and body (handles MIME-encoded subjects)
- Extracts links from the email body
- Flags urgency-related keywords (e.g. "verify your account", "act now")
- Detects link-text vs actual-href mismatches (the classic "text says paypal.com, link goes elsewhere" trick)

## Status
Work in progress — learning project, building it piece by piece.

## Usage