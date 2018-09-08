# angr-static-analysis-for-vuzzer64

About
-----
This repository contains a Angr-based static analysis module developed during my internship at VU Amsterdam for their fuzzing tool Vuzzer. It supports both the 32bit and 64bit versions of Vuzzer.

Vuzzer 32bit: https://github.com/vusec/vuzzer
Vuzzer 64bit: https://github.com/vusec/vuzzer64


How to use BB-weight-angr?
--------------------------
First of all, install the following dependencies on the system. 

``` sudo pip2 install angr angrutils networkx ```

Then, in order to execute it, run the following command:

``` python2 BB-weight-angr.py path/to/binary ```
