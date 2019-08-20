<?php

require_once "config.php";

$username = $email = $phone = $password = $confirm_password = $captcha = "";
$username_err = $email_err = $phone_err = $password_err = $confirm_password_err = $captcha_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    //Username Validation
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } else{
        $username = trim($_POST["username"]);
        if (!preg_match("/^[a-zA-Z ]*$/",$username)) {
            $username_err = "Only letters are allowed"; 
        }
    }

    //Email Validation
    if(empty(trim($_POST["email"]))){
        $email_err = "Please enter email.";
    } else{
       
        $sql = "SELECT id from userlogin WHERE email = ?";

        if($stmt = mysqli_prepare($link, $sql)){

            mysqli_stmt_bind_param($stmt, "s", $param_email);

            $param_email = trim($_POST["email"]);

            //Email Format Validation
            if (!filter_var($param_email, FILTER_VALIDATE_EMAIL)) {
                $email_err = "Invalid email format"; 
            }

            if(mysqli_stmt_execute($stmt)){
               
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){

                    $email_err = "This email is already taken.";

                } else{

                    $email = trim($_POST["email"]);

                }
            } else{

                echo "Please try again later.";

            }

        }
    }
    
    //Phone Validation
    if(empty(trim($_POST["phone"]))){
        $phone_err = "Please enter your contact number.";
    } else{
        $phone = trim($_POST["phone"]);
    }

    //Password Validation
    if(empty(trim($_POST["password"]))){

        $password_err = "Please enter a password.";  

    } else{

        $password = trim($_POST["password"]);

        if(strlen($password) < 8){
            $password_err = "Password must be atleast 8 characters";
        }
    }
    
    //Re-confirm Password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }

    //Captcha Validation
    if($_POST && "all required variables are present") {
        session_start();
        if(empty(trim($_POST["captcha"]))){
            $captcha_err = "Please enter captcha number.";
        }
        else if($_POST['captcha'] != $_SESSION['digit']){
            $captcha_err = "Sorry, the CAPTCHA code entered was incorrect!";
        }
        //session_destroy();
    }

    //Register User
    if(empty($username_err) && empty($email_err) && empty($phone_err) && empty($password_err) && empty($confirm_password_err) && empty($captcha_err)){
        
        $sql = "INSERT INTO userlogin (username, email, phone, password) VALUES (?, ?, ?, ?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
           
            mysqli_stmt_bind_param($stmt, "ssis", $param_username, $param_email, $param_phone, $param_password);
            
            $param_username = $username;
            $param_email = $email;
            $param_phone = $phone;
            $param_password = password_hash($password, PASSWORD_DEFAULT); 
            
            if(mysqli_stmt_execute($stmt) && ($_POST['captcha'] == $_SESSION['digit'])){
                //header("location: login.php");

                echo "You are registered successfully";
                //echo "<meta http-equiv='refresh' content='0'>";
            } else{
                echo "Please try again later.";
            }
        }
  
        mysqli_stmt_close($stmt);
    }
   
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html>
<head>
    <title>Sign Up</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css">
    <style type="text/css">
    .box{
        border: 1px solid black;
    }
    </style>
</head>
<body>
    <div class="container">
        <br><br>
        <div class="row">
            <div class="col-lg-6 col-lg-offset-3 col-md-6 col-md-offset-3 col-sm-6 col-sm-offset-3 col-xs-6 col-xs-offset-3 box">

                <h2 style = "text-align: center;">Sign Up</h2> 

                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">

                    <!--field for username-->
                    <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                        <label>Username:</label>
                        <div class="input-group">
                            <div class="input-group-addon">
                                <span class="glyphicon glyphicon-user"></span>
                            </div>
                            <input type="text" name="username" class="form-control" placeholder="Enter your Name" value="<?php echo $username; ?>">
                            <span class="help-block"><?php echo $username_err; ?></span>
                        </div>
                    </div>    

                    <!--field for email-->
                    <div class="form-group <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>">
                        <label>Email:</label>
                        <div class="input-group">
                            <div class="input-group-addon">
                                <span class="glyphicon glyphicon-envelope"></span>
                            </div>
                            <input type="text" name="email" class="form-control" placeholder="Enter your Email" value="<?php echo $email; ?>">
                            <span class="help-block"><?php echo $email_err; ?></span>
                        </div>
                    </div>

                    <!--field for contact number-->
                    <div class="form-group  <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>">
                        <label>Contact Number:</label>
                        <div class="input-group">
                            <div class="input-group-addon">
                                <span class="glyphicon glyphicon-earphone"></span>
                            </div>
                            <input type="phone" name="phone" class="form-control" placeholder="Enter your Contact Number" value="<?php echo $phone; ?>">
                            <span class="help-block"><?php echo $phone_err; ?></span> 
                        </div>
                    </div>

                    <!--field for password-->
                    <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                        <label>Password:</label>
                        <div class="input-group">
                            <div class="input-group-addon">
                                <span class="glyphicon glyphicon-lock"></span>
                            </div>
                            <input type="password" name="password" class="form-control" placeholder="Enter Password" value="<?php echo $password; ?>">
                            <span class="help-block"><?php echo $password_err; ?></span>
                        </div>
                    </div>

                    <!--field for re-password-->
                    <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                        <label>Confirm Password:</label>
                        <div class="input-group">
                            <div class="input-group-addon">
                                <span class="glyphicon glyphicon-lock"></span>
                            </div>
                            <input type="password" name="confirm_password" class="form-control" placeholder="Re-Enter Password" value="<?php echo $confirm_password; ?>">
                            <span class="help-block"><?php echo $confirm_password_err; ?></span>
                        </div>
                    </div>

                    <!--field for captcha-->
                    <div class="form-group <?php echo (!empty($captcha_err)) ? 'has-error' : ''; ?>">
                        <label>Captcha</label><br>
                        <img src="captcha.php" width="120" height="30" border="1" alt="CAPTCHA">
                        <p>
                            <input type="text" name="captcha" placeholder=" Enter the above captcha" value="<?php echo $captcha_err; ?>">
                        </p>
                            <span class="help-block"><?php echo $captcha_err; ?></span>
                    </div>

                    <!--Submit Button-->
                    <div class="form-group">
                        <input type="submit" class="btn btn-primary" value="Submit">
                    </div>

                    <p>Already have an account? <a href="login.php">Login here</a>.</p>

                </form>
            </div>
        </div>
    </div> 
</body>
</html>