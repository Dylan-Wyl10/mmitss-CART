#include <algorithm>
#include "SolverDataManager.h"

const int transitWeight = 1;
const int truckWeight = 1;
const double MAXGREEN = 50.0;

SolverDataManager::SolverDataManager(/* args */)
{
}

/*
    - This method will obtain requested signal group information from the priority request list and store them in requestedSignalGroup list.
*/
void SolverDataManager::getRequestedSignalGroupFromPriorityRequestList(vector<RequestList> priorityRequestList)
{
    //vector<int>requestedSignalGroup;
    for (size_t i = 0; i < priorityRequestList.size(); i++)
        requestedSignalGroup.push_back(priorityRequestList[i].requestedPhase);
}

/*
    - This method is responsible for removing the duplicate signal group number from requestedSignalGroup list.
        -If there is multiple priority request for same signal group then there will be duplicate signal group in requestedSignalGroup list.
*/
void SolverDataManager::removeDuplicateSignalGroup()
{
    auto end = requestedSignalGroup.end();
    for (auto it = requestedSignalGroup.begin(); it != end; ++it)
        end = std::remove(it + 1, end, *it);

    requestedSignalGroup.erase(end, requestedSignalGroup.end());
}

/*
- This function is responsible for finding associated signal group from another ring for requested signal group
- At first all requested signal group information are stored in another temporary vector
- Associated signal group is obtained by +/- 4. If requested phase is in ring 1 add 4. If equested phase is in ring 2 substract 4.
- Check if the associated signal group is enabled for the intersection
- Append associated signal group information in the orignal signal group list.
- Remove the duplicate phase number
*/
void SolverDataManager::addAssociatedSignalGroup(vector<TrafficControllerData::TrafficSignalPlan> trafficSignalPlan)
{
    vector<int> tempListOfRequestedSignalGroup = requestedSignalGroup;
    int associatedSignalGroup{};
    int tempRequestedSignalGroup{};

    for (auto i = requestedSignalGroup.begin(); i != requestedSignalGroup.end(); ++i)
    {
        tempRequestedSignalGroup = *i;
        if (tempRequestedSignalGroup < 5)
        {
            associatedSignalGroup = tempRequestedSignalGroup + 4;
            vector<TrafficControllerData::TrafficSignalPlan>::iterator findSignalGroup = std::find_if(std::begin(trafficSignalPlan), std::end(trafficSignalPlan),
                                                                                                      [&](TrafficControllerData::TrafficSignalPlan const &p) { return p.phaseNumber == associatedSignalGroup; });
            if (findSignalGroup != trafficSignalPlan.end())
                tempListOfRequestedSignalGroup.push_back(associatedSignalGroup);
        }
        else
        {
            associatedSignalGroup = tempRequestedSignalGroup - 4;
            vector<TrafficControllerData::TrafficSignalPlan>::iterator findSignalGroup = std::find_if(std::begin(trafficSignalPlan), std::end(trafficSignalPlan),
                                                                                                      [&](TrafficControllerData::TrafficSignalPlan const &p) { return p.phaseNumber == associatedSignalGroup; });
            if (findSignalGroup != trafficSignalPlan.end())
                tempListOfRequestedSignalGroup.push_back(associatedSignalGroup);
        }
    }
    requestedSignalGroup = tempListOfRequestedSignalGroup;
    removeDuplicateSignalGroup();
}

/*
    - This function will increase the  value of green max by 15% if there is Transit or Truck in the priority request list.
*/
void SolverDataManager::modifyGreenMax(vector<TrafficControllerData::TrafficSignalPlan> trafficSignalPlan)
{
    for (auto i = requestedSignalGroup.begin(); i != requestedSignalGroup.end(); ++i)
    {
        vector<TrafficControllerData::TrafficSignalPlan>::iterator findSignalGroup = std::find_if(std::begin(trafficSignalPlan), std::end(trafficSignalPlan),
                                                                                                  [&](TrafficControllerData::TrafficSignalPlan const &p) { return p.phaseNumber == *i; });
        if (findSignalGroup != trafficSignalPlan.end())
            findSignalGroup->maxGreen = findSignalGroup->maxGreen * 1.15;
    }
}

/*
    - This function is responsible for creating Data file for glpk Solver based on priority request list and TCI data.
*/
void SolverDataManager::generateDatFile(vector<RequestList> priorityRequestList, vector<TrafficControllerData::TrafficConrtollerStatus> trafficControllerStatus, vector<TrafficControllerData::TrafficSignalPlan> trafficSignalPlan)
{
    // int temporaryPhase{};
    // vector<int> temporaryPhaseNumber{};
    // temporaryPhaseNumber = PhaseNumber;
    vector<int>::iterator it;
    int vehicleClass{}; //to match the old PRSolver
    int numberOfRequest{};
    int ReqSeq = 1;

    getRequestedSignalGroupFromPriorityRequestList(priorityRequestList);
    removeDuplicateSignalGroup();
    addAssociatedSignalGroup(trafficSignalPlan);
    modifyGreenMax(trafficSignalPlan);


    ofstream fs;
    fs.open("NewModelData.dat", ios::out);
    fs << "data;\n";
    for (size_t i = 0; i < trafficControllerStatus.size(); i++)
    {
        fs << "param SP1:=" << trafficControllerStatus[i].startingPhase1 << ";" << endl;
        fs << "param SP2:=" << trafficControllerStatus[i].startingPhase2 << ";" << endl;
        fs << "param init1:=" << trafficControllerStatus[i].initPhase1 << ";" << endl;
        fs << "param init2:=" << trafficControllerStatus[i].initPhase2 << ";" << endl;
        fs << "param Grn1 :=" << trafficControllerStatus[i].elapsedGreen1 << ";" << endl;
        fs << "param Grn2 :=" << trafficControllerStatus[i].elapsedGreen2 << ";" << endl;
    }
    // if (bEVStatus == true)
    // {
    //     trafficSignalPlan_EV.insert(trafficSignalPlan_EV.end(), trafficSignalPlan.begin(), trafficSignalPlan.end());
    //     sort(plannedEVPhases.begin(), plannedEVPhases.end()); //arrange the numbers in ascending order

    //     for (size_t j = 0; j < plannedEVPhases.size(); j++)
    //     {
    //         temporaryPhase = plannedEVPhases.at(j);
    //         it = std::find(temporaryPhaseNumber.begin(), temporaryPhaseNumber.end(), temporaryPhase);
    //         if (it != temporaryPhaseNumber.end())
    //         {
    //             temporaryPhaseNumber.erase(it);
    //         }
    //     }

    //     for (size_t i = 0; i < temporaryPhaseNumber.size(); i++)
    //     {
    //         temporaryPhase = temporaryPhaseNumber.at(i);

    //         vector<TrafficControllerData::TrafficSignalPlan>::iterator findSignalGroupOnList = std::find_if(std::begin(trafficSignalPlan_EV), std::end(trafficSignalPlan_EV),
    //                                                                                                         [&](TrafficControllerData::TrafficSignalPlan const &p) { return p.phaseNumber == temporaryPhase; });

    //         if (findSignalGroupOnList != trafficSignalPlan_EV.end())
    //             trafficSignalPlan_EV.erase(findSignalGroupOnList);
    //     }

    //     //Find the maximum ETA and ETA duration from among all the EV
    //     findMaximumETAofEV();
    //     // for (size_t k = 0; k < priorityRequestList.size(); k++)
    //     // {
    //     //     temporaryVehicleETA.push_back(priorityRequestList[k].vehicleETA);
    //     //     temporaryVehicleETA_Duration.push_back(priorityRequestList[k].vehicleETA_Duration);
    //     // }

    //     // maxEV_ETA = *max_element(temporaryVehicleETA.begin(), temporaryVehicleETA.end());
    //     // maxEV_ETA_Duration = *max_element(temporaryVehicleETA_Duration.begin(), temporaryVehicleETA_Duration.end());

    //     fs << "param y          \t:=";
    //     for (size_t i = 0; i < trafficSignalPlan_EV.size(); i++)
    //         fs << "\t" << trafficSignalPlan_EV[i].phaseNumber << "\t" << trafficSignalPlan_EV[i].yellowChange;
    //     fs << ";\n";

    //     fs << "param red          \t:=";
    //     for (size_t i = 0; i < trafficSignalPlan_EV.size(); i++)
    //         fs << "\t" << trafficSignalPlan_EV[i].phaseNumber << "\t" << trafficSignalPlan_EV[i].redClear;
    //     fs << ";\n";

    //     fs << "param gmin      \t:=";
    //     for (size_t i = 0; i < trafficSignalPlan_EV.size(); i++)
    //         fs << "\t" << trafficSignalPlan_EV[i].phaseNumber << "\t" << trafficSignalPlan_EV[i].minGreen;
    //     fs << ";\n";

    //     fs << "param gmax      \t:=";

    //     if (MAXGREEN > maxEV_ETA + maxEV_ETA_Duration)
    //     {
    //         for (size_t i = 0; i < trafficSignalPlan_EV.size(); i++)
    //             fs << "\t" << trafficSignalPlan_EV[i].phaseNumber << "\t" << MAXGREEN;
    //     }

    //     else
    //     {
    //         for (size_t i = 0; i < trafficSignalPlan_EV.size(); i++)
    //             fs << "\t" << trafficSignalPlan_EV[i].phaseNumber << "\t" << maxEV_ETA + maxEV_ETA_Duration;
    //     }

    //     fs << ";\n";
    // }

    // else
    // {
        fs << "param y          \t:=";
        for (size_t i = 0; i < trafficSignalPlan.size(); i++)
            fs << "\t" << trafficSignalPlan[i].phaseNumber << "\t" << trafficSignalPlan[i].yellowChange;
        fs << ";\n";

        fs << "param red          \t:=";
        for (size_t i = 0; i < trafficSignalPlan.size(); i++)
            fs << "\t" << trafficSignalPlan[i].phaseNumber << "\t" << trafficSignalPlan[i].redClear;
        fs << ";\n";

        fs << "param gmin      \t:=";
        for (size_t i = 0; i < trafficSignalPlan.size(); i++)
            fs << "\t" << trafficSignalPlan[i].phaseNumber << "\t" << trafficSignalPlan[i].minGreen;
        fs << ";\n";

        fs << "param gmax      \t:=";
        for (size_t i = 0; i < trafficSignalPlan.size(); i++)
            fs << "\t" << trafficSignalPlan[i].phaseNumber << "\t" << trafficSignalPlan[i].maxGreen;
        fs << ";\n";
    // }

    fs << "param priorityType:= ";

    if (!priorityRequestList.empty())
    {
        for (size_t i = 0; i < priorityRequestList.size(); i++)
        {
            vehicleClass = 0;
            numberOfRequest++;
            if (priorityRequestList[i].basicVehicleRole == 16)
            {
                numberOfTransitInList++;
                vehicleClass = 2;
            }

            else if (priorityRequestList[i].basicVehicleRole == 9)
            {
                numberOfTruckInList++;
                vehicleClass = 3;
            }

            fs << numberOfRequest;
            fs << " " << vehicleClass << " ";
        }
        while (numberOfRequest < 10)
        {
            numberOfRequest++;
            fs << numberOfRequest;
            fs << " ";
            fs << 0;
            fs << " ";
        }
        fs << " ;  \n";
    }

    else
    {
        fs << " 1 0 2 0 3 5 4 0 5 0 6 0 7 0 8 0 9 0 10 0 ; \n";
    }

    fs << "param PrioWeigth:=  1 1 2 ";
    if (numberOfTransitInList > 0)
        fs << transitWeight / numberOfTransitInList;
    else
    {
        fs << 0;
    }
    fs << " 3 ";
    if (numberOfTruckInList > 0)
        fs << truckWeight / numberOfTruckInList;
    else
    {
        fs << 0;
    }
    fs << " 4 0 5 0 6 0 7 0 8 0 9 0 10 0 ; \n";

    fs << "param Rl (tr): 1 2 3 4 5 6 7 8:=\n";

    if (!priorityRequestList.empty())
    {
        for (size_t i = 0; i < priorityRequestList.size(); i++)
        {
            fs << ReqSeq << "  ";
            for (size_t j = 0; j < trafficSignalPlan.size(); j++)
            {
                if (priorityRequestList[i].requestedPhase == trafficSignalPlan[j].phaseNumber)
                    fs << priorityRequestList[i].vehicleETA << "\t";
                else
                    fs << ".\t";
            }
            ReqSeq++;
            fs << "\n";
        }
    }

    fs << ";\n";
    ReqSeq = 1;

    fs << "param Ru (tr): 1 2 3 4 5 6 7 8:=\n";

    if (!priorityRequestList.empty())
    {
        for (size_t i = 0; i < priorityRequestList.size(); i++)
        {
            fs << ReqSeq << "  ";
            for (size_t j = 0; j < trafficSignalPlan.size(); j++)
            {
                if (priorityRequestList[i].requestedPhase == trafficSignalPlan[j].phaseNumber)
                    fs << priorityRequestList[i].vehicleETA + priorityRequestList[i].vehicleETA_Duration << "\t";
                else
                    fs << ".\t";
            }
            ReqSeq++;
            fs << "\n";
        }
    }

    fs << ";\n";
    fs << "end;";
    fs.close();
}



SolverDataManager::~SolverDataManager()
{
}