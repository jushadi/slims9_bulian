<?php
/**
 *
 * Forgot Password for Administrator
 * Copyright (C) 2020 Eddy Subratha (eddy.subratha@gmail.com)
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

use SLiMS\Url;
use SLiMS\Captcha\Factory as Captcha;

// be sure that this file not accessed directly
if (!defined('INDEX_AUTH')) {
    die("can not access this file directly");
} elseif (INDEX_AUTH != 1) { 
    die("can not access this file directly");
}

// required file
require SIMBIO.'simbio_DB/simbio_dbop.inc.php';

// https connection (if enabled)
if ($sysconf['https_enable']) {
    simbio_security::doCheckHttps($sysconf['https_port']);
}

// Captcha initialize
$captcha = Captcha::section('forgot');

// Variable to hold feedback script
$feedback_script = '';

// start the output buffering for main content
ob_start();

if (isset($_POST['resetPass'])) {
    $email = $dbs->escape_string($_POST['currentmail']);
    if (!$email) {
        $message = addslashes(__('Please enter a valid email address.'));
        $feedback_script = "<script>toastr.error('{$message}');</script>";
    } else {
        try {
            if ($captcha->isSectionActive() && $captcha->isValid() === false) {
                throw new Exception(__('Captcha incorrect.'));
            }
                
            // Validate current email
            $_q = $dbs->query("SELECT user_id, realname FROM user WHERE email='{$email}'");

            if ($_q->num_rows === 0) {
                // Email not found, provide generic success message for security
                // This prevents attackers from guessing registered emails
                $message = addslashes(__('If a matching account was found, an email has been sent to reset your password.'));
                $feedback_script = "<script>toastr.info('{$message}');</script>";
            } else {
                // Email found, proceed to send reset link
                $file_d = $_q->fetch_assoc();
                $name = $file_d['realname'];
                $salt = bin2hex(random_bytes(32));
                $_sql_update_salt = sprintf("UPDATE user SET forgot = '{$salt}', last_update = NOW() WHERE email = '%s'", $email);
                writeLog('staff', $name, 'Forgot Password', $name.' has been requested a new password.', 'Password', 'Request');
                $_update_q = $dbs->query($_sql_update_salt);
                    
                /*
                 * =================================================================
                 * KODE LAMA (DIJADIKAN KOMENTAR)
                 * Kode ini bergantung pada layanan eksternal slims.web.id
                 * =================================================================
                 *
                // force scheme to https
                // if (Url::getPort() == '443') Url::$forceHttps = true;

                // set hook process variable
                $hookProcess = Client::withHeaders(["X-API-KEY" => $salt])
                    ->post('https://slims.web.id/mailer/forgot.php', [
                        'url' => (string)Url::getSlimsFullUri(), 'salt' => $salt,
                        'email' => $email, 'name' => $name
                    ]);

                if ($hookProcess->getStatusCode() !== 200 || $hookProcess->getContent() == 'false') {
                    $error = (isDev() ? ' ' . __('Error') . ' : ' . $hookProcess->getError() : ' ' . __('Error not available'));
                    throw new Exception(__('Cannot send the email. Please try again.') . $error);
                }
                */

                // =================================================================
                // KODE BARU (PERBAIKAN) - Menggunakan setelan email lokal SLiMS
                // =================================================================
                require_once LIB . 'PHPMailer/src/Exception.php';
                require_once LIB . 'PHPMailer/src/PHPMailer.php';
                require_once LIB . 'PHPMailer/src/SMTP.php';
                
                $mail = SLiMS\Mail::getInstance();
                $mail->addAddress($email, $name);
                
                $mail->Subject = $sysconf['library_name'] . ' - ' . __('Reset Password Instruction');
                $resetLink = rtrim(Url::getSlimsBaseUri(), '/') . '/index.php?p=newpass&token=' . urlencode($salt);
                
                $mail->Body = sprintf(__('Hi %s,'), $name) . "\n\n";
                $mail->Body .= __('You have requested a password reset. Please click the link below to create a new password:') . "\n";
                $mail->Body .= $resetLink . "\n\n";
                $mail->Body .= __('If you did not request this, please ignore this email.') . "\n\n";
                $mail->Body .= __('Regards,') . "\n";
                $mail->Body .= $sysconf['library_name'];
                
                if (!$mail->send()) {
                    throw new Exception(__('Cannot send the email.') . ' Mailer Error: ' . $mail->ErrorInfo);
                }

                $message = addslashes(__('<strong>Congratulations!</strong> An instruction has been sent to your email. Please check your inbox.'));
                $feedback_script = "<script>toastr.success('{$message}');</script>";
            }

        } catch (Exception $e) {
            $message = addslashes($e->getMessage());
            $feedback_script = "<script>toastr.error('{$message}');</script>";
        }
        
    }
}
?>
<div id="loginForm">
    <noscript>
        <div style="font-weight: bold; color: #FF0000;"><?php echo __('Your browser does not support Javascript or Javascript is disabled. Application won\'t run without Javascript!'); ?><div>
    </noscript>
    <div class="mb-3">
        <?php echo __('If you need help resetting your password, we can help by sending you a link to reset it.'); ?>
    </div>
    <form action="index.php?p=forgot" method="post" novalidation>
        <div class="heading1"><?php echo __('Your email address'); ?></div>
        <div class="login_input"><input type="email" name="currentmail" id="currentmail" class="login_input" required /></div>
        <?php 
        if ($captcha->isSectionActive()) { ?>
            <div class="captchaAdmin">
                <?= $captcha->getCaptcha() ?>
            </div>
            <?php
        }
        ?>
        <div class="marginTop">
        <input type="submit" name="resetPass" value="<?php echo __('Reset my password'); ?>" class="loginButton" />
        <a class="forgotButton" href="index.php?p=login"><?php echo __('Cancel') ?></a>
        </div>
    </form>
    <?php 
    // Menampilkan script notifikasi toast setelah form
    echo $feedback_script; 
    ?>
</div>
<script type="text/javascript">jQuery('#currentmail').focus();</script>

<?php
// main content
$main_content = ob_get_clean();

// page title
$page_title = __('Forgot My Password').' | '.$sysconf['library_name'];

// Memuat template
if ($sysconf['template']['base'] == 'html') {
    // create the template object
    $template = new simbio_template_parser($sysconf['template']['dir'].'/'.$sysconf['template']['theme'].'/login_template.html');
    // assign content to markers
    $template->assign('<!--PAGE_TITLE-->', $page_title);
    $template->assign('<!--CSS-->', $sysconf['template']['css']);
    $template->assign('<!--MAIN_CONTENT-->', $main_content);
    // print out the template
    $template->printOut();
} else if ($sysconf['template']['base'] == 'php') {
    require_once $sysconf['template']['dir'].'/'.$sysconf['template']['theme'].'/login_template.inc.php';
}

exit();
