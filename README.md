BouncyCastleBenchmark
=====================

Introduction
============
This is a quick Visual Studio 2012 solution that compares .NET AES encryption with BouncyCastle 1.7 AES ciphers.

This is NOT any official version of BouncyCastle in any way. It's just a project when I needed to compare performance of BouncyCastle in .NET 4.5 for AES-GCM mode. There is a VAST amount of code that this projects doesn't benchmark, like public key cryptography, hash algorithms etc.

Instead of just linking the BouncyCastle (BC) .dll from NuGet, I've included the BC source itself to aid in profiling, debugging in, making changes etc. Please read the license inside the BC project - it's not my code, some other fantastic folks have written that.

License:
========
This solution is licensed under the MIT license. Check License.txt. BC has it's own license, check that too.