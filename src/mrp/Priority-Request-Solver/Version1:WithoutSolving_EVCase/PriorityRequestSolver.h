/***********************************************************************************
 © 2019 Arizona Board of Regents on behalf of the University of Arizona with rights
       granted for USDOT OSADP distribution with the Apache 2.0 open source license.
**********************************************************************************
  PriorityRequestSolver.h
  Created by: Debashis Das
  University of Arizona   
  College of Engineering
  This code was developed under the supervision of Professor Larry Head
  in the Systems and Industrial Engineering Department.
  Revision History:
  1. 
*/

#pragma once

#include <iostream>
#include <vector>
#include "TrafficSignalPlan.h"
#include "RequestList.h"
#include "Schedule.h"
#include <sstream>

using std::cout;
using std::endl;
using std::string;
using std::stringstream;
using std::vector;
// using std::fstream;
using std::ifstream;
using std::ios;
using std::ofstream;

class PriorityRequestSolver
{
private:
    int noOfPhase{};
    int numberOfTransitInList{};
    int numberOfTruckInList{};
    int noOfPhasesInRing1{};
    int noOfPhasesInRing2{};
    int noOfEVInList{};
    string scheduleJsonString{};
    bool bEVStatus{};

    vector<RequestList> priorityRequestList;
    // vector<Schedule::GLPKSchedule> glpkSchedule;
    // vector<Schedule::GLPKSchedule>requestedVehicleCall;
    vector<Schedule::TCISchedule> ring1_TCISchedule;
    vector<Schedule::TCISchedule> ring2_TCISchedule;
    vector<TrafficControllerData::TrafficConrtollerStatus> trafficControllerStatus;
    vector<TrafficControllerData::TrafficSignalPlan> trafficSignalPlan;
    vector<TrafficControllerData::TrafficSignalPlan> trafficSignalPlan_EV;
    vector<int> PhaseNumber;
    vector<double> PedWalk;
    vector<double> PedClear;
    vector<double> MinGreen;
    vector<double> Passage;
    vector<double> MaxGreen;
    vector<double> YellowChange;
    vector<double> RedClear;
    vector<int> PhaseRing;
    vector<int> requestedSignalGroup;
    vector<int> plannedEVPhases;
    vector<int> P11;
    vector<int> P12;
    vector<int> P21;
    vector<int> P22;
    vector<int> EV_P11;
    vector<int> EV_P12;
    vector<int> EV_P21;
    vector<int> EV_P22;
    vector<double> singleEV_PhaseDuration_Ring1;
    vector<double> singleEV_PhaseDuration_Ring2;
    vector<double> leftCriticalPoints_PhaseDuration_Ring1;
    vector<double> leftCriticalPoints_PhaseDuration_Ring2;
    vector<double> rightCriticalPoints_PhaseDuration_Ring1;
    vector<double> rightCriticalPoints_PhaseDuration_Ring2;
    vector<double> leftCriticalPoints_GreenTime_Ring1;
    vector<double> leftCriticalPoints_GreenTime_Ring2;
    vector<double> rightCriticalPoints_GreenTime_Ring1;
    vector<double> rightCriticalPoints_GreenTime_Ring2;
    vector<int> plannedSignalGroupInRing1;
    vector<int> plannedSignalGroupInRing2;
    // vector<int> a;

public:
    PriorityRequestSolver();
    ~PriorityRequestSolver();

    void createPriorityRequestList(string jsonString);
    bool findEVInList();
    void modifyPriorityRequestList();
    void getEVPhases();
    void getCurrentSignalStatus();
    void getRequestedSignalGroupFromPriorityRequestList();
    void removeDuplicateSignalGroup();
    void addAssociatedSignalGroup();
    void modifyGreenMax();
    void generateDatFile();
    double GetSeconds();
    void GLPKSolver();
    bool GLPKSolutionValidation();
    void readOptimalSignalPlan();
    void obtainRequiredSignalGroup();
    void createEventList();
    string createScheduleJsonString();
    // void split(string strToSplit);
    void readCurrentSignalTimingPlan();
    void generateEVModFile();
    void generateModFile();
    void printSignalPlan();
    void printvector();
    int getNoOfEVInList();
    int getRequestedSignalGroupSize();
    int getEVRingBarrierGroup();
    void getEVTrafficSignalPlan();
};
