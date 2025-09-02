<?php
/**
 *
 * Librarian login page
 * Copyright (C) 2007,2008  Arie Nugraha (dicarve@yahoo.com), Hendro Wicaksono (hendrowicaksono@yahoo.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Modified by Jushadi Arman Saz 202509021600
 */

// be sure that this file not accessed directly
if (!defined('INDEX_AUTH')) {
    die("can not access this file directly");
}

if (!class_exists('simbio_dbop')) {
    require SIMBIO.'simbio_DB/simbio_dbop.inc.php';
}

$token = $_GET['token'] ?? '';
$is_token_valid = false;
$user_data = null;
$feedback_script = '';
$error_message = '';
$update_success = false;

if (!empty($token)) {
    $php_timezone = new DateTimeZone(date_default_timezone_get());
    $one_hour_ago = new DateTime('now', $php_timezone);
    $one_hour_ago->modify('-1 hour');
    $limit_time_string = $one_hour_ago->format('Y-m-d H:i:s');

    $stmt = $dbs->prepare("SELECT user_id, realname, email FROM user WHERE forgot = ? AND last_update > ?");
    $stmt->bind_param('ss', $token, $limit_time_string);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $is_token_valid = true;
        $user_data = $result->fetch_assoc();
    } else {
        $error_message = __('Invalid or expired reset token.');
    }
} else {
    $error_message = __('Reset token not provided.');
}

if (isset($_POST['updatePassword']) && $is_token_valid) {
    $passwd = trim($_POST['newPasswd']);
    $passwd2 = trim($_POST['newPasswd2']);
    $message = '';

    if (empty($passwd)) {
        $message = __('New password cannot be empty!');
    } else if ($passwd !== $passwd2) {
        $message = __('Password confirmation does not match. See if your Caps Lock key is on!');
    } else {
        $hashed_password = password_hash($passwd, PASSWORD_DEFAULT);
        $update_stmt = $dbs->prepare("UPDATE user SET passwd = ?, last_update = NOW(), forgot = NULL WHERE forgot = ?");
        $update_stmt->bind_param('ss', $hashed_password, $token);
        
        if ($update_stmt->execute()) {
            writeLog('staff', $user_data['realname'], 'Login', 'Change password SUCCESS for user '.$user_data['realname'], 'Password', 'Update');
            $update_success = true;
            $message = addslashes(__('Password has been updated successfully. Redirecting to login page...'));
            $login_url = 'index.php?p=login';
            
            $feedback_script = <<<HTML
            <script>
            $(document).ready(function() {
                if (typeof toastr !== 'undefined') {
                    toastr.options = { "timeOut": 3000, "progressBar": true };
                    toastr.success('{$message}');
                    setTimeout(function() {
                        window.location.href = '{$login_url}';
                    }, 3000);
                } else {
                    window.location.href = '{$login_url}';
                }
            });
            </script>
            HTML;

        } else {
            $message = __('Failed to update password. Please contact the administrator.');
        }
    }
    
    if ($message && !$update_success) {
        $safe_message = addslashes($message);
        $feedback_script = "<script>$(document).ready(function() { toastr.error('{$safe_message}'); });</script>";
    }
}

$page_title = __('Create New Password').' | '.$sysconf['library_name'];
ob_start();
?>
<div class="card">
    <div class="card-header"><?php echo __('Librarian - Create New Password'); ?></div>
    <div class="card-body">
        <?php if (!$is_token_valid): ?>
            <div class="alert alert-danger">
                <?php echo $error_message; ?><br>
                <small><?php echo __('Please request a new password reset link.'); ?></small>
            </div>
            <a href="index.php?p=login" class="btn btn-secondary"><?php echo __('Back to Login') ?></a>
        <?php elseif ($update_success): ?>
            <div class="alert alert-success">
                <?php echo __('Password Updated Successfully'); ?><br>
                <small><?php echo __('You will be redirected to the login page shortly.'); ?></small>
            </div>
        <?php else: ?>
            <form action="index.php?p=newpass&token=<?php echo htmlspecialchars($token); ?>" method="post">
                <div class="form-group row">
                    <label class="col-sm-4 col-form-label"><?php echo __('New Password'); ?></label>
                    <div class="col-sm-8">
                        <input type="password" name="newPasswd" class="form-control" required autofocus />
                    </div>
                </div>
                <div class="form-group row">
                    <label class="col-sm-4 col-form-label"><?php echo __('Confirm New Password'); ?></label>
                    <div class="col-sm-8">
                        <input type="password" name="newPasswd2" class="form-control" required />
                    </div>
                </div>
                <div class="form-group row">
                    <div class="col-sm-8 offset-sm-4">
                        <input type="submit" name="updatePassword" value="<?php echo __('Update Password'); ?>" class="btn btn-primary" />
                    </div>
                </div>
            </form>
        <?php endif; ?>
    </div>
</div>
<?php
$main_content = ob_get_clean();
$main_content .= $feedback_script;


if ($sysconf['template']['base'] == 'php') {
    require_once $sysconf['template']['dir'].'/'.$sysconf['template']['theme'].'/index_template.inc.php';
} else {
    $template = new simbio_template_parser($sysconf['template']['dir'].'/'.$sysconf['template']['theme'].'/index_template.html');
    $template->assign('', $page_title);
    $template->assign('', $main_content);
    $template->printOut();
}
exit();
