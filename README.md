# sumFE_v2
Functional Encryption Scheme for IoT Devices

# Experiments Overview

The experiments implemented in this project aim at implementing a lightweight Functional Encryption Scheme to be used as part of our Distributed Access Control Scheme

## dependencies

The functionalities of the scripts in this work are built on top of the Contiki-NG IoT operating system. To this end, to successfully run the experiments on the sensor device, Contiki-NG has to be downloaded from https://github.com/contiki-ng/contiki-ng. Code in this section is written in the C programming language. All the encryption schemes utilized are based on the Tinycrypt cryptograhic library.

* `ecc.c`: implementation of the Elliptic Curve Cryptography (ECC) encryption scheme 

Tinycrypt library: https://github.com/intel/tinycrypt

# Run sensor experiments

* Specifiy the IoT sensor board and target platform being used for the experiments. This work uses Nordic Semi-Conductor nrf52840dk board
    `make TARGET=nrf52840  BOARD=dk savetarget`
    
* Run the the script to run through a number of iterations of the core cryptographic components. Take note of the usb port that the IoT device is connected to (e.g. USB1):\
    `make sumFE.upload PORT="/dev/ttyUSB1"`

* Log into the sensor to view results of the tests:\
    `make login`


# Credits

## Authors

<!-- * Eugene Frimpong (Tampere University, Tampere, Finland)
* Alexandros Bakas (Tampere University, Tampere, Finland) -->

