#!/bin/bash

sudo airmon-ng stop wlp4s0mon && sudo ifconfig wlp4s0 down && sudo iwconfig wlp4s0 mode managed && sudo ifconfig wlp4s0 up && sudo service NetworkManager restart

