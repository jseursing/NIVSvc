# NIVSvc
NIVSvc is a non-invasive anti cheat service in the form of an dynamically-linked library. This anti cheat does not sniff active processes, threads, nor files. The purpose of this library is to detect any potential process/file manipulation from within the application's memory space.

The library currently detects:
* Library Injection
* Memory Manipulation
* Debugger activity

A test application which utilizes this library is included.
