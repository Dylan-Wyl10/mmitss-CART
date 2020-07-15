#!/bin/bash
#############################################################################################
#                                                                                           
# NOTICE:  Copyright 2018 Arizona Board of Regents on behalf of University of Arizona.      
# All information, intellectual, and technical concepts contained herein is and shall       
# remain the proprietary information of Arizona Board of Regents and may be covered         
# by U.S. and Foreign Patents, and patents in process.  Dissemination of this information          
# or reproduction of this material is strictly forbidden unless prior written permission    
# is obtained from Arizona Board of Regents or University of Arizona.                       
#                                                                                           
# mmitss_docker_make_all_x86.sh                                                                     
# Created by Niraj Altekar                                                                  
# Transportation Research Institute                                                         
# Systems and Industrial Engineering                                                        
# The University of Arizona                                                                 
#                                                                                           
# This code was develop under the supervision of Professor Larry Head                       
# in the Transportation Research Institute.                                                 
#                                                                                           
# Operational Description:                                                                   
# This script builds all mmitss applications (vehicle, intersection, and common),
# under the x86 environment. The primary reason for such builds is development and testing.
# This script can not be used in the ARM architecture based devices.                                                                                                  
#############################################################################################

# Define colors:
red='\033[0;31m'
green='\033[0;32m'
nocolor='\033[0m'

#######################################################################################
echo "Building Priority Request Generator Server..."
cd ./../src/simulation/priority-request-generator-server
# Clean the folder and build for linux.
make clean &> /dev/null
make linux &> /dev/null
# Indicate Success/Failure of the build
if [ "$?" -eq "0" ]; then
    mv M_PriorityRequestGeneratorServer ../../../bin/PriorityRequestGeneratorServer/x86
	echo -e "${green}Successful${nocolor}"
else
	echo -e "${red}Failed${nocolor}"
fi
# Remove the .o files to keep the folders clean
rm ./*.o &> /dev/null
# Return back to original directory to go over the process again for another one
cd - &> /dev/null
sleep 1s
#######################################################################################

#######################################################################################
echo "Building Message Distributor..."
cd ./../src/simulation/message-distributor
# Clean the folder and build for linux.
pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed M_MessageDistributor.py  &> /dev/null
# Indicate Success/Failure of the build
if [ "$?" -eq "0" ]; then
    mv dist/M_MessageDistributor  ../../../bin/MessageDistributor/x86
	echo -e "${green}Successful${nocolor}"
else
	echo -e "${red}Failed${nocolor}"
fi
# Remove the .o files to keep the folders clean
rm -r build dist *.spec &> /dev/null
rm -r __pycache__ &> /dev/null
# Return back to original directory to go over the process again for another one
cd - &> /dev/null
sleep 1s
#######################################################################################