#!/usr/bin/php -q
<?php
// === CONFIGURATION ===
$logDir = '/var/log/httpd';
$tailLines = 200;
$threshold = 5;
$blockEnabled = true;
$blocklistFile = '/var/log/apache-blocked-ips.txt';
$whitelistFile = '/etc/apache-attack-whitelist.txt';
$slackToken = 'xoxb-xxxxxxxxxxxxxxxx';
$slackChannel = '#alerts';

$autoBlockPatterns = [
    'cgi-bin/wp-login.php',
    'wp-includes/.*/wp-login.php',
    'wp-content/upgrade/wp-login.php',
    'wp-content/plugins/.*/landing-page/templates/.*\.js',
    'wp-includes/.*\.php',
    'wp-admin/includes/.*' ];

$flagPatterns = [
    'wp-login.php',
    'xmlrpc.php' ];

$cloudflareCidrs = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14' ];

function ipInCidr($ip, $cidr) {
    list($subnet, $bits) = explode('/', $cidr);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask;
    return ($ip & $mask) === $subnet;
}

function isCloudflareIp($ip, $cidrs) {
    foreach ($cidrs as $cidr) {
        if (ipInCidr($ip, $cidr)) return true;
    }
    return false;
}

function loadList($file) {
    return file_exists($file) ? array_map('trim', file($file)) : [];
}
function sendSlackAlert($ip, $url, $domain, $count, $token, $channel) {
    $msg = <<<EOT
:rotating_light: *Blocked IP:* $ip
*Domain:* $domain
*URL:* $url
*Count:* $count
EOT;

    $payload = json_encode([
        "channel" => $channel,
        "text" => $msg,
        "mrkdwn" => true
    ]);

    $ch = curl_init("https://slack.com/api/chat.postMessage");
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $token",
        "Content-Type: application/json"
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);

    echo "[Slack] Response: $result\n";
    if ($err) echo "[Slack] CURL Error: $err\n";
}

$blocklist = loadList($blocklistFile);
$whitelist = loadList($whitelistFile);
$blockCounts = [];
$logs = glob("$logDir/*access_log");

foreach ($logs as $logFile) {
    $lines = explode(" ", trim(shell_exec("tail -n $tailLines " . escapeshellarg($logFile))));
    $domain = basename($logFile) === 'access_log' ? 'unmatched' : preg_replace('/-access_log.*/', '', basename($logFile));
    foreach ($lines as $line) {
        if (!preg_match('/^([0-9.]+).*?"(?:GET|POST) ([^"]+)/', $line, $m)) continue;
        [$_, $ip, $url] = $m;
        if (in_array($ip, $whitelist) || isCloudflareIp($ip, $cloudflareCidrs)) continue;
        foreach ($autoBlockPatterns as $pattern) {
            if (preg_match("#$pattern#", $url)) {
                $blockCounts[$ip][] = [$url, $domain];
                break;
            }
        }
    }
}

foreach ($blockCounts as $ip => $entries) {
    if (count($entries) >= $threshold && !in_array($ip, $blocklist)) {
        $first = $entries[0];
        echo "[!] $ip triggered " . count($entries) . " times on {$first[1]}: {$first[0]} ";
        if ($blockEnabled) {
            shell_exec("sudo iptables -C INPUT -s $ip -j DROP 2>/dev/null || sudo iptables -I INPUT -s $ip -j DROP");
            file_put_contents($blocklistFile, "$ip\n", FILE_APPEND);
            sendSlackAlert($ip, $first[0], $first[1], count($entries), $slackToken, $slackChannel);
        }
    }
}
?>
