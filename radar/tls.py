import asyncio
import ssl
from urllib.parse import urlsplit

from cryptography import x509


async def inspect_tls(url, timeout=7, address=None):
    parsed = urlsplit(url)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(address or parsed.hostname, parsed.port or 443,
                                                      ssl=context, server_hostname=parsed.hostname,
                                                      ssl_handshake_timeout=timeout)
            cert = x509.load_der_x509_certificate(writer.get_extra_info("ssl_object").getpeercert(binary_form=True))
            try:
                names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                names = []
            return {"status": "TLS_SERVICE_OBSERVED", "certificate_verified": False,
                    "sans": sorted(set(names)), "not_after": cert.not_valid_after_utc.isoformat()}
    except (OSError, TimeoutError, ValueError) as exc:
        return {"status": "TLS_NOT_ESTABLISHED", "error": type(exc).__name__}
    finally:
        if writer:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, TimeoutError):
                pass
