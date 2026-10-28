# QR Shield

**Track:** Cybersecurity and Digital Safety
**Hackathon:** PromptWars x KickToTech 2026

## Problem
Many students and UPI users in India scan QR codes without checking them.
Scammers use fake QR codes to send people to phishing links or to trick them
into making payments. Sometimes We also scan qr codes for wifi without knowing its strength, connectivity which can lead to your data loss.

## Who it is for
Students ,everyday UPI users, and anybody who scans a QR code in shops, on posters and in messages.

## What it does
QR Shield lets you check a QR code before you trust it. You upload an image,
use your camera, or paste a screenshot. The app reads the QR code and shows:
- A verdict (Safe, Caution or Danger) with a Threat Level percentage
- Plain-language reasons for every warning
- Special handling for UPI payment QR codes (shows payee, amount, and a
  reminder to only pay if you trust the person)
- Special handling for WiFi QR codes (warns about open or weak networks)

## How the checks work
All checks run in your browser using simple rules:
- **HTTP instead of HTTPS**
- **IP address instead of a domain name**
- **URL shorteners**
- **Lookalike (punycode) domains**
- **Suspicious words** such as login, verify, KYC, reward
- **UPI links:** reads the payee name, UPI ID and amount from the link
- **WiFi QR codes:** reads the network name and security type

## How to run
1. Download or clone this repository.
2. Open `index.html` in Google Chrome. No installation is needed.
3. Upload a QR image, use the camera, or paste a screenshot with Ctrl+V.

## How to test
Try QR codes that contain these fictional examples:
- `https://www.wikipedia.org` (Safe)
- `https://bit.ly/3DemoXyz` (Caution)
- `http://192.168.10.5/login/verify-kyc` (Danger)
- `upi://pay?pa=demo.person@fakebank&pn=Demo%20Payee&am=250` (Payment QR)
- `WIFI:S:Demo-Cafe;T:WPA;P:fakepass123;H:false;;` (WiFi QR)

## Limitations
- This is a rule-based check. It cannot guarantee that a QR code is safe.
- QR Shield never opens or visits the link, so it cannot check what a website contains.
- Camera scanning needs browser permission and good lighting.
- This app cannot prevent each and every type of qr Phishing.

## Privacy
The QR code is decoded in your browser. Nothing is uploaded or sent to a server.
All sample data in this project is fictional.

## AI tools used
- Google Antigravity
- Claude for Reasearch and brainstorming

## Originality
I built this project during the
hackathon using AI tools to help write the code. I tested it and can explain
how it works. i have tested this on multiple sample qrs to chech it works and so that my solution satisfies all claims made.
