<!DOCTYPE html>
<html>
<head>
<title>vt scan</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="HandheldFriendly" content="True">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="virus total url analyser">
<style>
body {margin:40px; background-color:lightgrey; color:#black; font-family: Arial, Helvetica, sans-serif;}
h1 {color:black;}
code {background-color:#eee; border:1px solid; display:inline-block; padding:10px;}
</style>
</head>
<body>
<h1>VT URL 0.2</h1>
<form action="index.php" method="post">
    <i>Note: one url/ip per line, sanitized links will be handled</i><br><br>
    <textarea id="submit" name="urlInput" rows="20" cols="80"></textarea>
    <br><br>
    <input type="submit" name="submitUrls" value="Submit Link" /><br>
</form>

</form>
<br><hr><br>
<pre><code>
<?php
    //TODO
    //sanitize inputs
    // NOTE: need to install php curl - consult nginx error logs
    // sudo apt-get install php-curl
    // restart nginx
    if($_SERVER['REQUEST_METHOD'] == "POST" and isset($_POST['submitUrls']))
    {
        processUrlsAsync();
    }

    function processUrls() {
        ob_start();
        $url_input = strip_tags(trim($_POST[ "urlInput" ] ) );
        // textarea input adds carriage returns >:(
        $url_input = str_replace("\r", '', $url_input);
        echo 'Analyzing: <br>' . $url_input . '<br>';
        $uid = getUniqID();
        //$uid = "testid";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'localhost:4141/vturl/'.$uid);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $url_input);
        $resp = curl_exec($ch);
        if (curl_errno($ch)) {
            echo 'Error:' . curl_error($ch);
        }
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ( $status != 200 ) {
            die("\nError: failed with status $status\nResponse: $resp");
        }
        echo $resp + '\n\n';
        echo 'output: <a href="output/' . $uid . '.txt">' . 'output/' . $uid . '.txt</a>';
    }

    function processUrlsAsync() {
        ob_start();
        $url_input = strip_tags(trim($_POST[ "urlInput" ] ) );
        // textarea input adds carriage returns >:(
        $url_input = str_replace("\r", '', $url_input);
        $uid = getUniqID();
        //$uid = "testid";
        $url = 'localhost:4141/vturl/'.$uid;
        echo 'submitted, this will take time to complete...<br><br>';
        echo 'output: <a href="output/' . $uid . '.txt">' . 'output/' . $uid . '.txt</a>';
        asyncRequest($url, $url_input);
    }

    function asyncRequest($url, $payload) {
        //https://gist.githubusercontent.com/DavidLindbom/6352119/raw/a63a67bbe29f7a8da2a5f50cff14b1e0b14b7732/curl.php
        $cmd = "curl -X POST -H 'Content-Type: application/json'";
        $cmd.= " -d '" . $payload . "' " . "'" . $url . "'";
        $cmd .= " > /dev/null 2>&1 &";
        exec($cmd, $output, $exit);
        return $exit == 0;
    }

    function getUniqID($length = 6) {
        if (function_exists("random_bytes")) {
            $bytes = random_bytes(ceil($length / 2));
        } elseif (function_exists("openssl_random_pseudo_bytes")) {
            $bytes = openssl_random_pseudo_bytes(ceil($length / 2));
        } else {
            throw new Exception("no cryptographically secure random function available");
        }
        return substr(bin2hex($bytes), 0, $length);
    }
?>
</code></pre>
</body>
</html>