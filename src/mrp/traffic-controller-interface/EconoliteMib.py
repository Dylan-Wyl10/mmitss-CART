"""
***************************************************************************************

 © 2019 Arizona Board of Regents on behalf of the University of Arizona with rights
       granted for USDOT OSADP distribution with the Apache 2.0 open source license.

***************************************************************************************

EconoliteMib.py
Created by: Niraj Vasant Altekar
University of Arizona   
College of Engineering

This code was developed under the supervision of Professor Larry Head
in the Systems and Industrial Engineering Department.

***************************************************************************************

Description:
------------
This module stores the OIDs of vendor specific NTCIP objects. These are special objects
which are not available in the standard. 

***************************************************************************************
"""

## NOTE: Explain the need of using this MIB.

# Object that controls the broadcast of SPAT blob from the controller:
# For MMITSS applications, this object needs to be set to the value = 6.
asc3ViiMessageEnable            =   "1.3.6.1.4.1.1206.3.5.2.9.44.1.1"

# Object that returns the ID of the currently active timing plan:
CUR_TIMING_PLAN                 =   "1.3.6.1.4.1.1206.3.5.2.1.22.0"   

# Phase Parameters:
# If the value returned by CUR_TIMING_PLAN object = 'x', and we need information about phase 'p',
# then for using any of the following objects, x.p needs to be added to the corresponding OID.
# For example, if the current timing plan ID = 4, and we need PEDWALK time of phase 3, 
# then the corresponding OID would be "1.3.6.1.4.1.1206.3.5.2.1.2.1.3.4.3"
PHASE_PARAMETERS_PHASE_NUMBER   =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.2."
PHASE_PARAMETERS_PEDWALK        =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.3."
PHASE_PARAMETERS_PEDCLEAR       =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.6."
PHASE_PARAMETERS_MIN_GRN        =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.9."   
PHASE_PARAMETERS_PASSAGE        =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.13."
PHASE_PARAMETERS_MAX_GRN        =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.15."
PHASE_PARAMETERS_YELLOW_CHANGE  =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.18."
PHASE_PARAMETERS_RED_CLR        =   "1.3.6.1.4.1.1206.3.5.2.1.2.1.19."
