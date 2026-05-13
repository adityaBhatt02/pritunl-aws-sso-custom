# Custom Pritunl AWS SSO Integration

Features:
- AWS Identity Center SSO
- User self-service VPN profile download
- Admin-only local login
- VPN connect-time SSO validation
- Stolen profile protection
- Custom nginx reverse proxy flow

Architecture:
User -> AWS SSO -> Profile Download
VPN Client -> Browser SSO -> Connect Validation
