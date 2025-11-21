// Block forbidden IPs.
<?php
$blocked = [
    '37.19.199.131'
];

$ip = $_SERVER['REMOTE_ADDR'];

function cidr_match($ip, $cidr) {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    list($subnet, $mask) = explode('/', $cidr);
    return (ip2long($ip) & ~((1 << (32 - $mask)) - 1)) === ip2long($subnet);
}

foreach ($blocked as $rule) {
    if (cidr_match($ip, $rule)) {
        http_response_code(403);
        exit;
    }
}
?>