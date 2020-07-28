---
layout: post
title: "PHP Phar Injections: Abusing file_exists() and unlink() to gain RCE"
excerpt: "PHP Phar Injections explained with 2 different examples. The first one in a custom app, and the second one in Wordpress"
categories: [tutorials]
comments: true
tags: [php, phar injection, real world app, rce]
---


#### Intro

In 2018, Sam Thomas presented a deserialization attack without `unserialize()` even existing in the code. And that can be done through `PHP Archive (Phar)` files. Just like `JAR` files are in `Java`, `Phar` files are in `PHP`. In order to explain how `Phar injections` work, you first need to understand what deserialization is and how attacking it works. So I'm first going to explain that, and then I'm going to dive into `Phar injections` and after that, I've included 2 different examples on a custom app and on a Wordpress Application. At the end of the post I'm also going to write about a few protection methods, and also included some resources where you can read & learn more about these types of vulnerabilities.

> https://nvd.nist.gov/vuln/detail/CVE-2018-20148

#### What is (de)serialization

Serialization in PHP (and any other language) simply turns objects into strings that can be passed around the website, for example you may find serialized data in cookies. There are 2 main functions in PHP to do that.

> serialize($object) # serializes the given object

> unserialize($string) # deserializes the given string and turns it into an object

Take the following code for example, it takes the object and serializes it. 

{% highlight php %}
<?php 

// example class
class User {
  public $username = "John";
  public $access = "0";
}
// call the class
$user = new User;
// serialize it
echo serialize($user);

?>
{% endhighlight %}


The output of this script would be this:
![Phar](/img/php-phar-1.png)

Now the code below would take the serialized data and use it

{% highlight php %}
<?php 

// a class where we are going to redirect later
class SystemManagment {

  public $remove_logs = "rm /tmp/site/*.log"
  // dangerous function
  public function __destruct($command) {
    echo system($this->remove_logs);
  }
}

// example class
class User {
  public $username = "John";
  public $access = "0";
}

// this would be for example encoded in cookies or somewhere where user has access on it
$serialized_data = $argv[1];

$object = unserialize($serialized_data);

echo "Username: ".$object->username."\n";
echo "Access to post: ". ($object->access ? 'true' : 'false'); # dumb access
echo "\n";
?>
{% endhighlight %}

Now note in the script, we deserialize the object and print the username on the screen. But we also have another class called `SystemManagment` which contains a function that executes commands on the system. That is called gadget in our case, because that's where we are going to redirect the object in order to gain code execution. 

First let's run the script with the previously serialized data

![Phar](/img/php-phar-2.png)

Now time to create a php script that creates a serialized object, that when deserialized attempts to run a command through the `SystemManagment` class



-explain phar injections

-explain how to exploit them using a custom app you are going to write

-explain how to exploit a phar injection vuln in a real world app

-explain some protections

-put some resources for further read