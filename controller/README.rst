===================================
Reverse Syscall Fuzzer - Controller
===================================


Introduction
============
..
  TODO: add an introduction

A controller script for the reverse syscall fuzzer


Setup
=====
setup environment
-----------------
.. code-block::

   virtualenv -p python3 env
   source env/bin/activate
   pip3 install -r requirement.txt


files to change
---------------
- config.yaml: paths
- target.py: target config/ client functions