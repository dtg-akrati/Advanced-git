<?php

session_start();
 

if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: welcome.php");
    exit;
}
 
require_once "config.php";
 
$email = $password = $email = $phone = "";
$email_err = $password_err = "";
 
if($_SERVER["REQUEST_METHOD"] == "POST"){
    
    //Username Validation
    if(empty(trim($_POST["email"]))){
        $email_err = "Please enter email.";
    } else{
        $email = trim($_POST["email"]);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $email_err = "Invalid email format"; 
        }
    }
    
    //Password Validation
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter your password.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    //Login User
    if(empty($email_err) && empty($password_err)){
    
        $sql = "SELECT id, username, email, phone, password FROM userlogin WHERE email = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            
            mysqli_stmt_bind_param($stmt, "s", $param_email);
          
            $param_email = $email;
            
            if(mysqli_stmt_execute($stmt)){

                mysqli_stmt_store_result($stmt);
               
                if(mysqli_stmt_num_rows($stmt) == 1){                    
                    
                    mysqli_stmt_bind_result($stmt, $id, $username, $email, $phone, $hashed_password);

                    if(mysqli_stmt_fetch($stmt)){
                        if(password_verify($password, $hashed_password)){
                           
                            //session_start();
                            
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["email"] = $email;                            
                           
                            header("location: welcome.php");
                        } else{
                            
                            $password_err = "The password you entered was not valid.";
                        }
                    }
                } else{
                   
                    $email_err = "No account found with that email.";
                }
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
    <title>Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
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

                <h2 style="text-align: center;">Login</h2> 

                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">

                    <!--field for username-->
                    <div class="form-group <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>">
                        <label>Email</label>
                         <div class="input-group">
                            <div class="input-group-addon">
                                <span class="glyphicon glyphicon-user"></span>
                            </div>
                            <input type="email" name="email" class="form-control" placeholder="Enter your Email" value="<?php echo $email; ?>">
                            <span class="help-block"><?php echo $email_err; ?></span>
                        </div>
                    </div>    

                    <!--field for password-->
                    <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                        <label>Password</label>
                        <div class="input-group">
                            <div class="input-group-addon">
                                <span class="glyphicon glyphicon-lock"></span>
                            </div>
                            <input type="password" name="password" class="form-control" placeholder="Enter Password" value="<?php echo $password; ?>">
                            <span class="help-block"><?php echo $password_err; ?></span>
                        </div>
                    </div>

                    <!--login button-->
                    <div class="form-group">
                        <input type="submit" class="btn btn-primary" value="Login" name="check">
                    </div>

                    <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>

                </form>
            </div>
        </div>
    </div>    
</body>
</html>