# Import system libraries
import json
import sys
import time

# Import local modules
from PullFromIntersection import PullFromIntersection
from PushToCyverse import PushToCyverse
from PushToServer import PushToServer
from Scheduler import Scheduler

# Define constants
DEBUGGING_ROADSIDE = False
DEBUGGING_SERVER = False
SLEEP_TIME_SEC = 3600

def get_roadside_config(config:dict):
    """
    takes a config dictionary and returns the variables related to roadside deployment (push to server).
    If there is any error in the configuration, returns a quadruple of -1 with a console output of the exception
    """
    try:
        server = config["DataTransfer"]["server"]
        intersection = config["DataTransfer"]["intersection"]
        startHour = config["DataTransfer"]["StartTime"]["hour"]
        startMinute = config["DataTransfer"]["StartTime"]["minute"]
        return server, intersection, startHour, startMinute
    except Exception as e:
        print(e)
        return -1, -1, -1, -1

def get_server_pull_config(config:dict):
    """
    takes a config dictionary and returns the variables related to server deployment (pull from intersections).
    If there is any error in the configuration, returns a quadruple of -1 with a console output of the exception
    """
    try:
        server = config["DataTransfer"]["server"]
        intersection = config["DataTransfer"]["intersection"]
        startHour = config["DataTransfer"]["StartTime_FromIntersections"]["hour"]
        startMinute = config["DataTransfer"]["StartTime_FromIntersections"]["minute"]
        return server, intersection, startHour, startMinute
    except Exception as e:
        print(e)
        return -1, -1, -1, -1

def get_server_cyverse_push_config(config:dict):
    """
    takes a config dictionary and returns the variables related to server deployment (push to CyVerse).
    If there is any error in the configuration, returns a quadruple of -1 with a console output of the exception
    """
    try:
        server = config["DataTransfer"]["server"]
        intersection = config["DataTransfer"]["intersection"]
        startHour = config["DataTransfer"]["StartTime_ToCyverse"]["hour"]
        startMinute = config["DataTransfer"]["StartTime_ToCyverse"]["minute"]
        return server, intersection, startHour, startMinute
    except Exception as e:
        print(e)
        return -1, -1, -1, -1    

if __name__=="__main__":

    # Select appropriate configuration file:
    if DEBUGGING_ROADSIDE and DEBUGGING_ROADSIDE:
        print("Invalid debugging configuration!")
        exit()
    elif DEBUGGING_ROADSIDE: 
        configFilename = "test/mmitss-phase3-master-config-roadside.json"
    elif DEBUGGING_SERVER:
        configFilename = "test/mmitss-phase3-master-config-server.json"
    else: 
        configFilename = "/nojournal/bin/mmitss-phase3-master-config.json"
    
    # Open the configuration file and read it's contents into a dictionary
    with open(configFilename, 'r') as configFile:
        config = json.load(configFile)

    # Start an instance of the Scheduler class
    scheduler = Scheduler()

    # Get the application platform from the config file
    applicationPlatform = config["ApplicationPlatform"]

    if applicationPlatform == "roadside":
        
        # Parse configuration parameters related to roadside deployment
        server, intersection, startHour, startMinute = get_roadside_config(config)
        
        # If the configuration parsing is successful:
        if server != -1 or intersection != -1 or startHour != -1 or startMinute != -1: 
            
            # Create an instance of the PushToServer class with configuration parameters provided as arguments
            pushToServer = PushToServer(server, intersection)
            
            # Schedule the daily execution of the transfer_data method of the pushToServer instance
            scheduler.schedule_daily_execution(pushToServer.transfer_data, startHour, startMinute)
            
            # Now there is nothing much to do. Sleep, wakeup, and repeat! (to keep the scheduler active)
            while True: time.sleep(SLEEP_TIME_SEC)

        # If the configuration parsing is unsuccessful, print a message to the console
        else: print("Could not schedule roadside data transfer!")
    
    elif applicationPlatform == "server":
        
        # create an activity variable that stores a boolean indicating whether any function (pull or push) 
        # from on the server is scheduled
        serverScheduled = False

        # If it is required to pull the data from intersections:
        if config["PullFromIntersections"] == True:
            
            # Parse the configuration items related to pulling the data from the server:
            server, intersection, startHour, startMinute = get_server_pull_config(config)

            # If parsing of the configuration items is successful:
            if server != -1 or intersection != -1 or startHour != -1 or startMinute != -1:
                
                # Create an instance of the PullFromIntersection class with configuration parameters provided in arguments
                pullFromIntersection = PullFromIntersection(server, intersection)

                # Schedule the daily execution of the transfer_data method of the instance of PullFromIntersection.
                scheduler.schedule_daily_execution(pullFromIntersection.transfer_data, startHour, startMinute)

                # Set the activity variable to be true
                serverScheduled = True
            
            # If parsing of configuration items is unsuccessful, print a message to the console:
            else: print("Could not schedule pull from intersection data transfer!")
        
        # If it is required to push the data to CyVerse:
        if config["PushToCyverse"] == True:
            
            # Parse the configuration items related to pulling the data from the server:
            server, intersection, startHour, startMinute = get_server_cyverse_push_config(config)
            
            # If parsing of the configuration parameters is successful:
            if server != -1 or intersection != -1 or startHour != -1 or startMinute != -1:
                
                # Create an instance of PushToCyverse class wit configuration parameters provided in arguments:
                pushToCyverse = PushToCyverse(server, intersection)

                # Schedule the daily execution of the transfer_data method of the PushToCyverse class
                scheduler.schedule_daily_execution(pushToCyverse.transfer_data, startHour, startMinute)
                
                # Set the activity variable to be true.
                serverScheduled = True
            
            # If parsing of configuration items is unsuccessful, print a message to the console:
            else: print("Could not schedule push to CyVerse data transfer!")

        # If activity variable is true, sleep, wakeup, and repeat - just to keep the background scheduler active
        if serverScheduled != False:
            while True: time.sleep(SLEEP_TIME_SEC)
        else: print("Nothing to schedule!")
    else:
        print("Nothing to schedule!")
        exit()