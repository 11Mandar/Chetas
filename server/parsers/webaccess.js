/**
 * Combined and Common Web Access Log Parser (Nginx, Apache, Envoy, Cloudflare)
 */

export function isWebAccess(logStr) {
  const str = logStr.trim();
  // Standard web access regex: IP - USER [TIMESTAMP] "METHOD URI HTTP/X.X" STATUS BYTES
  return /^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+\s+[^"]+"\s+\d{3}\s+\d+/i.test(str);
}

export function parseWebAccess(raw) {
  const str = raw.trim();
  // Regex for Nginx/Apache Combined Log Format
  const regex = /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP\/([0-9.]+))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;
  const match = str.match(regex);

  if (!match) {
    throw new Error('Invalid Combined Access Log format');
  }

  const [
    ,
    clientIp,
    identd,
    authUser,
    timeStr,
    method,
    requestUri,
    httpVersion,
    statusCode,
    bytesSent,
    referer,
    userAgent
  ] = match;

  const status = parseInt(statusCode, 10);
  const severity = status >= 500 ? 'ERROR' : status >= 400 ? 'WARNING' : 'INFORMATIONAL';

  return {
    format: 'Web-Access',
    vendor: 'Web Server',
    product: 'Nginx / Apache Gateway',
    event_type: 'HTTP_REQUEST',
    severity,
    attributes: {
      client_ip: clientIp,
      identd: identd !== '-' ? identd : null,
      auth_user: authUser !== '-' ? authUser : null,
      access_time: timeStr,
      http_method: method,
      request_uri: requestUri,
      http_version: httpVersion || '1.1',
      status_code: status,
      bytes_sent: bytesSent !== '-' ? parseInt(bytesSent, 10) : 0,
      referer: referer !== '-' ? referer : null,
      user_agent: userAgent !== '-' ? userAgent : null
    }
  };
}
