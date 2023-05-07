<?php
    include("database.php");
    session_start();

    if($_SERVER["REQUEST_METHOD"] == 'POST')
    {
        $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_SPECIAL_CHARS);
        $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_SPECIAL_CHARS);
        $username_err ="";
        $password_err ="";
        $login_err="";
            
        //Check if user already logged in
            if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] == true)
            {
                header("Location: Home.php");
                exit();
            }
             // Check if username is empty
            if(empty(trim($_POST["username"])))
            {
                 $username_err = "Kérlek add meg a felhasználóneved.";
            } 
            else
            {
                $username = trim($_POST["username"]);
            }
    
             // Check if password is empty
            if(empty(trim($_POST["password"])))
            {
                $password_err = "Kérlek add meg a jelszavad.";
            } 
            else
            {
                $password = trim($_POST["password"]);
            }

                if(empty($username_err) && empty($password_err))
                {
                    $sql = "SELECT * FROM users WHERE username =?";
                    if($stmt = mysqli_prepare($conn, $sql))
                    {
                        mysqli_stmt_bind_param($stmt, "s", $param_username);

                        $param_username = $username;

                        if(mysqli_stmt_execute($stmt))
                        {
                                mysqli_stmt_store_result($stmt);
                                if(mysqli_stmt_num_rows($stmt) == 1)
                                {                    
                                     mysqli_stmt_bind_result($stmt, $id, $username, $hash);
                                     if(mysqli_stmt_fetch($stmt))
                                     {
                                        if(password_verify($password, $hash))
                                        {
                                            session_start();
                                            $_SESSION["loggedin"] = true;
                                            $_SESSION["id"] = $id;
                                            $_SESSION["username"] = $username;

                                            header("Location: Home.php");
                                        }
                                        else
                                        {
                                            // Password is not valid, display a generic error message
                                            $login_err = "Hibás felhasználónév vagy jelszó.";
                                        }
                                     }
                                }
                                else
                                {
                                    //Username does not exist
                                    $login_err = "Hibás felhasználónév vagy jelszó.";
                                }
                        }
                        else
                        {
                            echo "Oops! Something went wrong. Please try again later.";
                        }

                        // Close statement
                     mysqli_stmt_close($stmt);

                }
        }
    }
    mysqli_close($conn);
    session_destroy();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log in</title>
</head>
    <body>
        <h1>Bejelentkezés</h1>
        <form action = "<?php htmlspecialchars($_SERVER["PHP_SELF"])?>" method = "post">
        <div class = "form-group">
            <label>Felhasználónév:</label><br>
            <input type="text" name="username" placeholder ="Felhasználónév" 
            class = "form-control <?php echo(!empty($username_err)) ? 'is-valid' : ''; ?>" value="<?php if(isset($username)){echo $username;}; ?>"><br>
            <span class="invalid-feedback"><?php if(isset($username_err)){echo $username_err;}; ?></span>
        </div>
        <div class = "form-group">
            <label>Jelszó:</label><br>
            <input type = "password" name = "password" placeholder = "Jelszó"
            class="form-control<?php echo(!empty($password_err)) ? 'is-valid' : ''; ?>"><br>
            <span class="invalid-feedback"><?php if(isset($password_err)){echo $password_err;} ?></span>
        </div>
        <div class = "form-group">
            <input type = "submit" name ="Log in" value ="Bejelentkezés">
        </div>
        </form>
    </body>
</html>