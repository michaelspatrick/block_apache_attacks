#!/usr/bin/php -q
<?php
// === CONFIGURATION ===
$logDir = '/var/log/httpd';
$tailLines = 200;
$threshold = 5;
$blockEnabled = true;
$blocklistFile = '/var/log/apache-blocked-ips.txt';
$whitelistFile = '/etc/apache-attack-whitelist.txt';
$slackToken = 'xoxb-xxxx-xxxx-xxxx';
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
