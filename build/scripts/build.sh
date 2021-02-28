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
# build.sh                                                                     
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
# under the arm environment. The primary reason for such builds is development and testing.
# This script can not be used in the x86 architecture based devices.                                                                                                  
#############################################################################################

# Define colors:
red='\033[0;31m'
green='\033[0;32m'
nocolor='\033[0m'

######################################################################################

read -p "Has lmmitss-initialize.sh script already been executed? (y or n):" lmmitssStatus

if [ "$lmmitssStatus" = "n" ]; then
echo "Please run lmmitss-initialize.sh script and then run this script. Exiting now!"
exit 0

else

    read -p "Build all applications? (y or n): " all
    if [ "$all" = "n" ]; then

    read -p "Build transceiver applications? (y or n): " common
    read -p "Build roadside applications? (y or n): " mrp
    read -p "Build vehicle applications? (y or n): " vsp
    read -p "Build simulation_server-tools applications? (y or n): " server

    else
    common=y
    mrp=y
    vsp=y
    server=y
    fi

    ######################################################################################

    ################################## COMMON APPLICATIONS ###############################


    if [ "$common" = "y" ]; then

	    echo "------------------------"
	    echo "TRANSCEIVER APPLICATIONS"
	    echo "------------------------"
	    ######################################################################################

	    echo "Building Message Encoder..."
	    cd ../../src/common/MsgTransceiver/MsgEncoder
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_MsgEncoder ../../../../build/bin/MsgEncoder/$PROCESSOR/M_MsgEncoder
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
	    echo "Building Wireless Message Decoder..."
	    cd ../../src/common/MsgTransceiver/MsgDecoder/WirelessMsgDecoder
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_WirelessMsgDecoder ../../../../../build/bin/WirelessMsgDecoder/$PROCESSOR/M_WirelessMsgDecoder
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
	    echo "Building V2X Data Collector..."
	    cd ../../src/common/v2x-data-collector
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed v2x-data-collector-main.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/v2x-data-collector-main  ../../../build/bin/V2XDataCollector/$PROCESSOR/M_V2XDataCollector
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

	    #######################################################################################
	    echo "Building System Interface..."
	    cd ../../src/system-interface
	    # Clean the folder and build for linux.
	    pyinstaller --add-data "templates:templates" --add-data "static:static" --additional-hooks-dir=. --onefile --windowed system-interface.py &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/system-interface  ../../build/bin/SystemInterface/$PROCESSOR/M_SystemInterface
		    echo -e "${green}Successful${nocolor}"
	    else
		    echo -e "${red}Failed${nocolor}"
	    fi
	    # Remove the files to keep the folders clean
	    rm -r build dist *.spec &> /dev/null
	    rm -r __pycache__ &> /dev/null
	    # Return back to original directory to go over the process again for another one
	    cd - &> /dev/null
	    sleep 1s
	    #######################################################################################
    fi

    ############################### INTERSECTION APPLICATIONS #############################
    if [ "$mrp" = "y" ]; then

	    echo "---------------------"
	    echo "ROADSIDE APPLICATIONS"
	    echo "---------------------"

	    #######################################################################################
	    echo "Building Priority Request Server..."
	    cd ../../src/mrp/priority-request-server
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_PriorityRequestServer ../../../build/bin/PriorityRequestServer/$PROCESSOR/M_PriorityRequestServer
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
	    echo "Building Priority Solver..."
	    cd ../../src/mrp/priority-request-solver
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_PriorityRequestSolver ../../../build/bin/PriorityRequestSolver/$PROCESSOR/M_PriorityRequestSolver
		    echo -e "${green}Successful${nocolor}"
	    else
		    echo -e "${red}Failed${nocolor}"
	    fi
	    # Remove the .o files to keep the folders clean
	    rm ./*.o &> /dev/null
	    # Return back to original directory to go over the process again for another one
	    cd - &> /dev/null
	    sleep 1s
	    ######################################################################################

	    #######################################################################################
	    echo "Building Snmp Engine..."
	    cd ../../src/mrp/snmp-engine
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_SnmpEngine ../../../build/bin/SnmpEngine/$PROCESSOR/M_SnmpEngine
		    echo -e "${green}Successful${nocolor}"
	    else
		    echo -e "${red}Failed${nocolor}"
	    fi
	    # Remove the .o files to keep the folders clean
	    rm ./*.o &> /dev/null
	    # Return back to original directory to go over the process again for another one
	    cd - &> /dev/null
	    sleep 1s
	    ######################################################################################

	    #######################################################################################
	    echo "Building Traffic Controller Interface..."
	    cd ../../src/mrp/traffic-controller-interface
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed traffic-controller-interface.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/traffic-controller-interface  ../../../build/bin/TrafficControllerInterface/$PROCESSOR/M_TrafficControllerInterface
		    echo -e "${green}Successful${nocolor}"
	    else
		    echo -e "${red}Failed${nocolor}"
	    fi
	    # Remove the .o files to keep the folders clean
	    rm -r build dist __pychache__ *.spec &> /dev/null
	    rm -r __pycache__ &> /dev/null
	    # Return back to original directory to go over the process again for another one
	    cd - &> /dev/null
	    sleep 1s
	    #######################################################################################

	    #######################################################################################
	    echo "Building Map Spat Broadcaster..."
	    cd ../../src/mrp/map-spat-broadcaster
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed map-spat-broadcaster.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/map-spat-broadcaster  ../../../build/bin/MapSpatBroadcaster/$PROCESSOR/M_MapSpatBroadcaster
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

	    #######################################################################################
	    echo "Building Signal Coordination Request Generator..."
	    cd ../../src/mrp/signal-coordination-request-generator
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed signal-coordination-request-generator.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/signal-coordination-request-generator  ../../../build/bin/SignalCoordinationRequestGenerator/$PROCESSOR/M_SignalCoordinationRequestGenerator
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

	    #######################################################################################
	    echo "Building V2X Data Ftp Client..."
	    cd ../../src/mrp/v2x-data-ftp-client
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed v2x-data-ftp-client-main.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/v2x-data-ftp-client-main  ../../../build/bin/V2XDataFtpClient/$PROCESSOR/M_V2XDataFtpClient
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
    fi

    ################################# VEHICLE APPLICATIONS ################################

    if [ "$vsp" = "y" ]; then
	    
	    echo "--------------------"
	    echo "VEHICLE APPLICATIONS"
	    echo "--------------------"

	    #######################################################################################
	    echo "Building Host BSM Decoder..."
	    cd ../../src/common/MsgTransceiver/MsgDecoder/HostBsmDecoder
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_HostBsmDecoder ../../../../../build/bin/HostBsmDecoder/$PROCESSOR/M_HostBsmDecoder
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
	    echo "Building Priority Request Generator..."
	    cd ../../src/vsp/priority-request-generator
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_PriorityRequestGenerator ../../../build/bin/PriorityRequestGenerator/$PROCESSOR/M_PriorityRequestGenerator
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
	    echo "Building Light Siren Status Manager..."
	    cd ../../src/vsp/light-siren-status-manager
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed light-siren-status-manager.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/light-siren-status-manager  ../../../build/bin/LightSirenStatusManager/$PROCESSOR/M_LightSirenStatusManager
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

	    #######################################################################################
	    echo "Building Data Compressor..."
	    cd ../../src/vsp/data-compressor
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed data-compressor.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/data-compressor  ../../../build/bin/DataCompressor/$PROCESSOR/M_DataCompressor
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
    fi

    ################################### SERVER TOOLS ##################################

    if [ "$server" = "y" ]; then

	    echo "------------------------------------"
	    echo "SIMULATION_SERVER-TOOLS APPLICATIONS"
	    echo "------------------------------------"

	    #######################################################################################
	    echo "Building Priority Request Generator Server..."
	    cd ../../src/server/priority-request-generator-server
	    # Clean the folder and build for linux.
	    make clean &> /dev/null

	    if [ "$PROCESSOR" = "arm" ]; then
		    make linux ARM=1 &> /dev/null
	    else
		    make linux &> /dev/null
	    fi

	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv M_PriorityRequestGeneratorServer ../../../build/bin/PriorityRequestGeneratorServer/$PROCESSOR/M_PriorityRequestGeneratorServer
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
	    cd ../../src/server/message-distributor
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed message-distributor.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/message-distributor  ../../../build/bin/MessageDistributor/$PROCESSOR/M_MessageDistributor
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

	    #######################################################################################
	    echo "Building Simulated BSM Blob Processor..."
	    cd ../../src/simulation/simulated-bsm-blob-processor
	    # Clean the folder and build for linux.
	    pyinstaller --hidden-import=pkg_resources.py2_warn --onefile --windowed simulated-bsm-blob-processor.py  &> /dev/null
	    # Indicate Success/Failure of the build
	    if [ "$?" -eq "0" ]; then
		    mv dist/simulated-bsm-blob-processor  ../../../build/bin/SimulatedBsmBlobProcessor/$PROCESSOR/M_SimulatedBsmBlobProcessor
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
    fi

    echo "Successfully built required applications!"
    echo "------------------------------------------"

    read -p "Build docker images? (y or n): " docker
    if [ "$docker" = "y" ]; then
	    read -p "Provide version tag: " versionTag

	    # Go to the mmitss directory
	    cd ../..

	    read -p "Build Base image? (y or n): " baseImage
	    read -p "Build MRP Field image? Needs transceiver and roadside applications. (y or n): " mrpFieldImage
	    read -p "Build VSP image? Needs transceiver and vehicle applications. (y or n): " vspImage
	    read -p "Build MRP Simulation image? Needs roadside applications. (y or n): " mrpSimulationImage
	    read -p "Build simulation_server-tools image? Needs simulation_server-tools applications. (y or n): " serverImage

	    if [ "$baseImage" = "y" ]; then
		    echo "Building Base image for $PROCESSOR"
		    docker build -t mmitssuarizona/mmitss-$PROCESSOR-base:$versionTag -f build/dockerfiles/$PROCESSOR/Dockerfile.base .
	    fi	

	    if [ "$mrpFieldImage" = "y" ]; then
		    echo "---------------------------------------"
		    echo "Building MRP-Field image for $PROCESSOR"
		    echo "---------------------------------------"
		    docker build -t mmitssuarizona/mmitss-mrp-$PROCESSOR:$versionTag -f build/dockerfiles/$PROCESSOR/Dockerfile.mrp .
	    fi	

	    if [ "$vspImage" = "y" ]; then
		    echo "---------------------------------"
		    echo "Building VSP image for $PROCESSOR"
		    echo "---------------------------------"
		    docker build -t mmitssuarizona/mmitss-vsp-$PROCESSOR:$versionTag -f build/dockerfiles/$PROCESSOR/Dockerfile.vsp .
	    fi	

	    if [ "$mrpSimulationImage" = "y" ]; then
		    echo "--------------------------------------------"
		    echo "Building MRP-Simulation image for $PROCESSOR"
		    echo "--------------------------------------------"
		    docker build -t mmitssuarizona/mmitss-mrp-simulation-$PROCESSOR:$versionTag -f build/dockerfiles/$PROCESSOR/Dockerfile.mrp-simulation .
	    fi	

	    if [ "$serverImage" = "y" ]; then
		    echo "-----------------------------------------------------"
		    echo "Building Simulation_Server-Tools image for $PROCESSOR"
		    echo "-----------------------------------------------------"
		    docker build -t mmitssuarizona/mmitss-simulation_server-tools-$PROCESSOR:$versionTag -f build/dockerfiles/$PROCESSOR/Dockerfile.simulation_server-tools .
	    fi	

    echo "Successfully built required docker images!"
    echo "-----------------------------------------------------------------------"

    fi
fi
