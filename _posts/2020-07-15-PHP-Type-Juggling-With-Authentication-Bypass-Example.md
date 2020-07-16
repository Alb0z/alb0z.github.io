---
layout: post
title: PHP Type-Juggling with Authentication Bypass example
excerpt: "Demo post displaying the various ways of highlighting code in Markdown."
categories: [tutorials]
comments: true
tags: [php, authentication bypass]
---

Did you know that a single missing character in your code can cause your authentication mechanism to be broken and give
attackers the ability to bypass it ? Or maybe exploit your API to get valuable information, or bypass your CSRF protection, or in some cases even gain RCE.
So today I'm going to explain these attacks, how to exploit them, and how to avoid them.

#### What is Type-Juggling

In PHP there are 2 main comparison methods called `loose` and `strict` comparisons 

> Loose Comparisons (==) - Doesn't check the type of the given data

> Strict Comparisons (===) - Does check the type of the given data

This kind of vulnerability lies on `Loose Comparisons`, and it happens because loose comparisons doesn't check the type of the data and will return `TRUE` if a string is compared to `0`. Example: `"0" == 0` will result in `TRUE` but also `"alb0z" == 0` will result in `TRUE`<br>
The image below shows the difference between `Loose Comparisons` and `Strict Comparisons`

![Difference between loose and strict comparisons](/img/Type-Juggling-1.png)