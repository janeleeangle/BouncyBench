BouncyBench
===========

Introduction
------------
This is a quick Visual Studio 2012 solution that compares .NET AES encryption with BouncyCastle C# AES ciphers. BouncyCastle itself is written by some other fantastic folks! Check out the contributors file inside BouncyCastle for their names.

This is NOT an official benchmark of BouncyCastle in any way. It's just a simple project for my need to compare performance of BouncyCastle in .NET 4.5 for AES-GCM mode. There is a VAST amount of code that this projects doesn't benchmark, like public key cryptography, hash algorithms etc. Instead of just linking the BouncyCastle (BC) .dll from NuGet, I've included the BouncyCastle source directly here  to aid in profiling, debugging in, making changes etc. This is **purely** for convenience for **this** project! So what is today the 'latest' from the official BouncyCastle C# CVS repository can be outdated in some time. If you want the latest, goto http://www.bouncycastle.org/csharp/ and look below for the CVS repository URL. While there, say thanks!

Contributions
-------------
Feel free to improve this in any way you want. This was written up quickly but it gets the job done. Send me your GIT pull request if you do so :)

License
-------
This solution is licensed under the MIT license. Pretty much you can do whatever you want but check License.txt for details.
BouncyCastle has it's own license, so check that out too.