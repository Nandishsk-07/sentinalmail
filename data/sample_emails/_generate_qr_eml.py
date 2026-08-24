"""Generate the QR-phishing .eml sample with an embedded QR code image."""
import base64
import io
import struct
import zlib


def _create_qr_png(url: str) -> bytes:
    """Create a minimal QR-code-like PNG image with the URL encoded
    as a visual pattern.  We build a *real* QR code using a pure-Python
    encoder so pyzbar / OpenCV can decode it during testing.

    Falls back to a synthetic grid pattern if anything goes wrong.
    """
    try:
        # --- tiny pure-Python QR encoder (ISO 18004, Version 1-M) ---
        # We'll use 'qrcode' if available; otherwise fall back.
        import qrcode
        qr = qrcode.QRCode(
            version=4,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        pass

    # --- Fallback: generate a minimal valid PNG with a grid pattern ---
    # This is a 21x21 "QR-like" grid baked into a real PNG so parsers
    # still see a valid image attachment.
    size = 210  # 21 modules * 10px each
    module = 10

    # Simple deterministic pattern seeded from the URL
    import hashlib
    seed = hashlib.sha256(url.encode()).digest()

    rows = []
    for y in range(size):
        row = []
        my = y // module
        for x in range(size):
            mx = x // module
            idx = (my * 21 + mx) % len(seed)
            is_black = seed[idx] & (1 << ((my * 21 + mx) % 8))
            row.append(0 if is_black else 255)
        rows.append(bytes([0] + row))  # filter byte 0 (None) per row

    raw = b"".join(rows)
    # Build PNG manually
    def _chunk(ctype, data):
        c = ctype + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n"
    png += _chunk(b"IHDR", ihdr)
    png += _chunk(b"IDAT", zlib.compress(raw, 9))
    png += _chunk(b"IEND", b"")
    return png


def build_eml(qr_png_bytes: bytes) -> str:
    """Assemble a multipart/related .eml with an inline QR code image."""
    b64_qr = base64.b64encode(qr_png_bytes).decode()
    # Wrap at 76 chars per RFC 2045
    b64_lines = "\n".join(
        b64_qr[i : i + 76] for i in range(0, len(b64_qr), 76)
    )

    return f"""\
Received: from mx3.targetcorp.com (mx3.targetcorp.com [198.51.100.51])
        by mailstore.targetcorp.com (Dovecot 2.3.20) with LMTP id pQ5rTz4JyWZmVAAA
        for <all-staff@targetcorp.com>;
        Sat, 22 Aug 2026 19:07:33 +0000 (UTC)
Received: from smtp-relay.company-1t-support.net (vps-node12.hostinger.com [153.92.0.44])
        by mx3.targetcorp.com (Postfix) with ESMTP id 4Wv8Rp1QTNz2wHk
        for <all-staff@targetcorp.com>;
        Sat, 22 Aug 2026 19:07:32 +0000 (UTC)
Received: from localhost (unknown [10.10.0.5])
        by smtp-relay.company-1t-support.net (Postfix) with ESMTP id 7E2F43A001C
        for <all-staff@targetcorp.com>;
        Sat, 22 Aug 2026 19:07:30 +0000 (UTC)
Authentication-Results: mx3.targetcorp.com;
        spf=fail (domain company-1t-support.net does not designate 153.92.0.44 as permitted sender) smtp.mailfrom=helpdesk@company-1t-support.net;
        dkim=none (no DKIM signature);
        dmarc=fail (p=NONE dis=NONE) header.from=company-1t-support.net
X-Spam-Status: Yes, score=7.4 required=5.0 tests=BAYES_95,SPF_FAIL,
        DKIM_NONE,HTML_IMAGE_ONLY_04,URIBL_DBL_PHISH autolearn=spam version=4.0.0
X-Spam-Score: 7.4
X-Spam-Flag: YES
Return-Path: <helpdesk@company-1t-support.net>
From: "IT Helpdesk - TargetCorp" <helpdesk@company-1t-support.net>
Reply-To: it-support-tc@protonmail.com
To: all-staff@targetcorp.com
Subject: =?UTF-8?B?8J+UkCBBY3Rpb24gUmVxdWlyZWQ6IFNjYW4gUVIgQ29kZSB0byBVcGRhdGUgTXVsdGktRmFjdG9yIEF1dGhlbnRpY2F0aW9u?=
Date: Sat, 22 Aug 2026 19:07:29 +0000
Message-ID: <qr-mfa-update.8a7b6c5d@company-1t-support.net>
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----=_QR_PHISH_OUTER_001"
X-Mailer: PHPMailer 6.8.1
X-Originating-IP: 153.92.0.44
X-Priority: 1
Importance: High

------=_QR_PHISH_OUTER_001
Content-Type: multipart/alternative; boundary="----=_QR_PHISH_INNER_001"

------=_QR_PHISH_INNER_001
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

ACTION REQUIRED: Multi-Factor Authentication Update
====================================================

Dear TargetCorp Employee,

As part of our mandatory security compliance upgrade, all employees
must re-enrol in Multi-Factor Authentication (MFA) by Monday,
Aug 24, 2026.

To complete the update:
  1. Open your phone's camera app.
  2. Scan the QR code in the HTML version of this email.
  3. Follow the on-screen instructions to verify your identity.

IMPORTANT: Accounts that have not completed MFA re-enrolment by the
deadline will be temporarily LOCKED for security purposes. You will
lose access to email, VPN, and all internal systems.

If you are unable to scan the QR code, visit:
https://company-1t-support.net/mfa/enroll?user=all-staff&token=a9f3e2

Thank you for your cooperation.

IT Helpdesk
TargetCorp Information Security
helpdesk@targetcorp.com | Ext. 4357

------=_QR_PHISH_INNER_001
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html>
<head><meta charset=3D"UTF-8">
<meta name=3D"viewport" content=3D"width=3Ddevice-width, initial-scale=3D1.=
0">
</head>
<body style=3D"margin: 0; padding: 0; background: #f0f2f5; font-family: Se=
goe UI, Tahoma, sans-serif;">
<table width=3D"100%" cellpadding=3D"0" cellspacing=3D"0" style=3D"padding:=
 40px 0; background: #f0f2f5;">
<tr><td align=3D"center">
<table width=3D"580" cellpadding=3D"0" cellspacing=3D"0" style=3D"backgroun=
d: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 12px r=
gba(0,0,0,0.08);">

<!-- Header -->
<tr><td style=3D"background: linear-gradient(135deg, #1a237e, #0d47a1); pad=
ding: 28px 32px;">
<h1 style=3D"color: #ffffff; margin: 0; font-size: 20px;">=F0=9F=94=90 IT =
Security =E2=80=94 MFA Update Required</h1>
<p style=3D"color: #bbdefb; margin: 6px 0 0; font-size: 13px;">TargetCorp =
Information Security Division</p>
</td></tr>

<!-- Body -->
<tr><td style=3D"padding: 32px;">
<p>Dear TargetCorp Employee,</p>
<p>As part of our <strong>mandatory security compliance upgrade</strong>, a=
ll employees must re-enrol in Multi-Factor Authentication (MFA) by <strong =
style=3D"color: #c62828;">Monday, Aug 24, 2026</strong>.</p>

<div style=3D"background: #fff8e1; border: 1px solid #ffcc02; border-radiu=
s: 6px; padding: 16px; margin: 20px 0;">
<p style=3D"margin: 0 0 4px; font-weight: 600; color: #e65100;">=E2=9A=A0=
=EF=B8=8F Accounts that have NOT completed re-enrolment by the deadline wil=
l be <span style=3D"color: #c62828;">temporarily LOCKED</span>.</p>
<p style=3D"margin: 0; font-size: 13px; color: #666;">You will lose access=
 to email, VPN, SharePoint, and all internal systems.</p>
</div>

<h3 style=3D"color: #1a237e;">Scan the QR Code Below</h3>
<p>Open your phone=E2=80=99s camera and scan this code to begin the MFA re=
-enrolment process:</p>

<div style=3D"text-align: center; margin: 24px 0; padding: 20px; backgroun=
d: #fafafa; border: 2px dashed #ccc; border-radius: 8px;">
<img src=3D"cid:qr-mfa-image" alt=3D"Scan QR Code for MFA Enrolment"
     width=3D"260" height=3D"260"
     style=3D"display: block; margin: 0 auto;">
<p style=3D"margin: 12px 0 0; font-size: 12px; color: #888;">Point your ph=
one camera at this code</p>
</div>

<p style=3D"font-size: 13px; color: #666;">Can=E2=80=99t scan? <a href=3D"=
https://company-1t-support.net/mfa/enroll?user=3Dall-staff&amp;token=3Da9f3=
e2" style=3D"color: #1565c0;">Click here to verify manually</a>.</p>
</td></tr>

<!-- Footer -->
<tr><td style=3D"padding: 20px 32px; background: #f5f5f5; border-top: 1px =
solid #eee; font-size: 11px; color: #999;">
<p>IT Helpdesk | TargetCorp Information Security<br>
helpdesk@targetcorp.com | Ext. 4357</p>
<p>This is an automated message. Please do not reply.</p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>

------=_QR_PHISH_INNER_001--

------=_QR_PHISH_OUTER_001
Content-Type: image/png; name="mfa_qr_code.png"
Content-Disposition: inline; filename="mfa_qr_code.png"
Content-Transfer-Encoding: base64
Content-ID: <qr-mfa-image>
X-Attachment-Id: qr-mfa-image

{b64_lines}

------=_QR_PHISH_OUTER_001--
"""


def main():
    phish_url = "https://company-1t-support.net/mfa/enroll?user=all-staff&token=a9f3e2"
    qr_png = _create_qr_png(phish_url)
    eml_content = build_eml(qr_png)

    out_path = r"d:\SIH\sentinel-mail\data\sample_emails\phish_qr_mfa.eml"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(eml_content)

    print(f"[OK] Written {len(eml_content):,} bytes -> {out_path}")
    print(f"     QR PNG size: {len(qr_png):,} bytes")


if __name__ == "__main__":
    main()
