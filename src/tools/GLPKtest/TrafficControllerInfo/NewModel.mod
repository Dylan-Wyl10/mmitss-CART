set P11:={1,2};  
set P12:={3,4};
set P21:={5,6};
set P22:={7,8};
set P:={ 1, 2, 3, 4, 5, 6, 7, 8};
set K  := {1..3};
set J  := {1..10};
set P2 := {1..8};
set T  := {1..10};
set E:={1,2};
set C :={1,2};
set CP:={2,6};
set CP1:={2};
set CP2:={6};
  
param y    {p in P}, >=0,default 0;
param red  {p in P}, >=0,default 0;
param gmin {p in P}, >=0,default 0;
param gmax {p in P}, >=0,default 0;
param init1,default 0;
param init2,default 0;
param Grn1, default 0;
param Grn2, default 0;
param SP1,  integer,default 0;
param SP2,  integer,default 0;
param M:=9999,integer;
param alpha:=100,integer;
param Rl{p in P, j in J}, >=0,  default 0;
param Ru{p in P, j in J}, >=0,  default 0;
param Cl1{p in CP, c in C}, >=0,  default 0;
param Cu1{p in CP, c in C}, >=0,  default 0;
param Cl2{p in CP, c in C}, >=0,  default 0;
param Cu2{p in CP, c in C}, >=0,  default 0;
param coordinationOn,:= 0;
param cycle, :=100;
param active_coord1{p in CP, c in C}, integer, :=(if (Cl1[p,c]>0 and coordinationOn=1) then	1 else	0);
param active_coord2{p in CP, c in C}, integer, :=(if (Cl2[p,c]>0 and coordinationOn=1) then	1 else	0);
param PrioType { t in T}, >=0, default 0;  
param PrioWeigth { t in T}, >=0, default 0;  
param priorityType{j in J}, >=0, default 0;  
param priorityTypeWeigth{j in J, t in T}, := (if (priorityType[j]=t) then PrioWeigth[t] else 0);  
param active_pj{p in P, j in J}, integer, :=(if Rl[p,j]>0 then 1 else	0);
param coef{p in P,k in K}, integer,:=(if  (((p<SP1 and p<5) or (p<SP2 and p>4 )) and k==1) or (((p<5 and SP1<=p) or (p>4 and SP2<=p)) and k==3) then 0 else 1);
param PassedGrn1{p in P,k in K},:=(if ((p==SP1 and k==1))then Grn1 else 0);
param PassedGrn2{p in P,k in K},:=(if ((p==SP2 and k==1))then Grn2 else 0);
param PassedGrn3{p in P,k in K},:=(if (p==SP1 and k==1) then (if (PassedGrn1[SP1,k] <= PassedGrn2[SP2,k]) then PassedGrn1[SP1,k] else PassedGrn2[SP2,k]) else 0);
param PassedGrn4{p in P,k in K},:=(if (p==SP2 and k==1) then (if (PassedGrn1[SP1,k] <= PassedGrn2[SP2,k]) then PassedGrn1[SP1,k] else PassedGrn2[SP2,k]) else 0);
param ReqNo:=sum{p in P,j in J} active_pj[p,j];
param CoordNo:= sum{p in CP1,c in C} active_coord1[p,c]+sum{p in CP2,c in C} active_coord2[p,c];
param sumOfGMax11, := sum{p in P11} (gmax[p]*coef[p,1]);
param sumOfGMax12, := sum{p in P12} (gmax[p]*coef[p,1]);
param sumOfGMax21, := sum{p in P21} (gmax[p]*coef[p,1]);
param sumOfGMax22, := sum{p in P22} (gmax[p]*coef[p,1]);
param barrier1GmaxSlack, := sumOfGMax11 - sumOfGMax21 ;
param barrier2GmaxSlack, := sumOfGMax12 - sumOfGMax22 ;
param gmaxSlack{p in P}, := (if coef[p,1]=0 then 0 else (if (p in P11) then gmax[p]*max(0,-barrier1GmaxSlack)/sumOfGMax11  else ( if (p in P21) then gmax[p]*max(0,+barrier1GmaxSlack)/sumOfGMax21  else ( if (p in P12) then gmax[p]*max(0,-barrier2GmaxSlack)/sumOfGMax12  else ( if (p in P22) then gmax[p]*max(0,barrier2GmaxSlack)/sumOfGMax22  else 0) ) ) )    ); 
param gmaxPerRng{p in P,k in K}, := (if (k=1) then gmax[p]+gmaxSlack[p] else	gmax[p]);
  
var t{p in P,k in K,e in E}, >=0;
var g{p in P,k in K,e in E}, >=0;
var v{p in P,k in K,e in E}, >=0;
var d{p in P,j in J}, >=0;
var theta{p in P,j in J}, binary;
var ttheta{p in P,j in J}, >=0;
var PriorityDelay;
var Flex;
var zeta1{p in CP1,c in C}, binary;
var zetatl{p in CP1,c in C}, >=0;
var zeta2{p in CP1,c in C}, binary;
var zetatu{p in CP1,c in C}, >=0;
var gamma1{p in CP2,c in C}, binary;
var gammatl{p in CP2,c in C}, >=0;
var gamma2{p in CP2,c in C}, binary;
var gammatu{p in CP2,c in C}, >=0;
var coordDelay1{p in CP1,c in C}, >=0;
var coordDelay2{p in CP2,c in C}, >=0;
  
s.t. initial{e in E,p in P:(p<SP1) or (p<SP2 and p>4)}: t[p,1,e]=0;  
s.t. initial1{e in E,p in P:p=SP1}: t[p,1,e]=init1;  
s.t. initial2{e in E,p in P:p=SP2}: t[p,1,e]=init2;  
s.t. Prec_11_11_c1{e in E,p in P11: (p+1)in P11 and p>=SP1  }:  t[p+1,1,e]=t[p,1,e]+v[p,1,e];
s.t. Prec_12_12_c1{e in E,p in P12: (p+1)in P12 and p>=SP1  }:  t[p+1,1,e]=t[p,1,e]+v[p,1,e];
s.t. Prec_21_21_c1{e in E,p in P21: (p+1)in P21 and p>=SP2  }:  t[p+1,1,e]=t[p,1,e]+v[p,1,e];
s.t. Prec_22_22_c1{e in E,p in P22: (p+1)in P22 and p>=SP2  }:  t[p+1,1,e]=t[p,1,e]+v[p,1,e];
s.t. Prec_11_12_c1{e in E,p in P12: (card(P12)+p)<=5 and p>SP1  }:  t[p,1,e]=t[2,1,e]+v[2,1,e];
s.t. Prec_11_22_c1{e in E,p in P22: (card(P22)+p)<=9 and p>SP2  }:  t[p,1,e]=t[2,1,e]+v[2,1,e];
s.t. Prec_21_12_c1{e in E,p in P12: (card(P12)+p)<=5 and p>SP1  }:  t[p,1,e]=t[6,1,e]+v[6,1,e];
s.t. Prec_21_22_c1{e in E,p in P22: (card(P22)+p)<=9 and p>SP2  }:  t[p,1,e]=t[6,1,e]+v[6,1,e];
s.t. Prec_11_11_c23{e in E,p in P11, k in K: (p+1)in P11 and k>1  }:  t[p+1,k,e]=t[p,k,e]+v[p,k,e];
s.t. Prec_12_12_c23{e in E,p in P12, k in K: (p+1)in P12 and k>1  }:  t[p+1,k,e]=t[p,k,e]+v[p,k,e];
s.t. Prec_21_21_c23{e in E,p in P21, k in K: (p+1)in P21 and k>1  }:  t[p+1,k,e]=t[p,k,e]+v[p,k,e];
s.t. Prec_22_22_c23{e in E,p in P22, k in K: (p+1)in P22 and k>1  }:  t[p+1,k,e]=t[p,k,e]+v[p,k,e];
s.t. Prec_11_12_c23{e in E,p in P12, k in K: coef[p,k]=1 and (card(P12)+p)=5 and k>1 }:  t[p,k,e]=t[2,k,e]+v[2,k,e];
s.t. Prec_11_22_c23{e in E,p in P22, k in K: coef[p,k]=1 and (card(P22)+p)=9 and k>1 }:  t[p,k,e]=t[2,k,e]+v[2,k,e];
s.t. Prec_21_12_c23{e in E,p in P12, k in K: coef[p,k]=1 and (card(P12)+p)=5 and k>1 }:  t[p,k,e]=t[6,k,e]+v[6,k,e];
s.t. Prec_21_22_c23{e in E,p in P22, k in K: coef[p,k]=1 and (card(P22)+p)=9 and k>1 }:  t[p,k,e]=t[6,k,e]+v[6,k,e];
s.t. Prec_12_11_c23{e in E,p in P11, k in K: (card(P11)+p+1)=4 and k>1 }:    t[p,k,e]=t[4,k-1,e]+v[4,k-1,e];
s.t. Prec_22_11_c23{e in E,p in P11, k in K: (card(P11)+p+1+4)=8 and k>1 }:  t[p,k,e]=t[8,k-1,e]+v[8,k-1,e];
s.t. Prec_12_21_c23{e in E,p in P21, k in K: (card(P21)+p+1-4)=4 and k>1 }:  t[p,k,e]=t[4,k-1,e]+v[4,k-1,e];
s.t. Prec_22_21_c23{e in E,p in P21, k in K: (card(P21)+p+1)=8 and k>1 }:    t[p,k,e]=t[8,k-1,e]+v[8,k-1,e];
s.t. PhaseLen{e in E,p in P, k in K}:  v[p,k,e]=(g[p,k,e]+y[p]+red[p])*coef[p,k];
s.t. GrnMax{e in E,p in P ,k in K}:  g[p,k,e]<=(gmaxPerRng[p,k]-PassedGrn3[p,k]-PassedGrn4[p,k])*coef[p,k]; 
s.t. GrnMin{e in E,p in P ,k in K}:  g[p,k,e]>=(gmin[p]-PassedGrn1[p,k]-PassedGrn2[p,k])*coef[p,k]; 
s.t. PrioDelay1{e in E,p in P,j in J: active_pj[p,j]>0}:    d[p,j]>=(t[p,1,e]*coef[p,1]+t[p,2,e]*(1-coef[p,1]))-Rl[p,j]; 
s.t. PrioDelay2{e in E,p in P,j in J: active_pj[p,j]>0}:    M*theta[p,j]>=Ru[p,j]-((t[p,1,e]+g[p,1,e])*coef[p,1]+(t[p,2,e]+g[p,2,e])*(1-coef[p,1]));
s.t. PrioDelay3{e in E,p in P,j in J: active_pj[p,j]>0}:    d[p,j]>= ttheta[p,j]-Rl[p,j]*theta[p,j];
s.t. PrioDelay4{e in E,p in P,j in J: active_pj[p,j]>0}:    g[p,1,e]*coef[p,1]+g[p,2,e]*(1-coef[p,1])>= (Ru[p,j]-Rl[p,j])*(1-theta[p,j]);
s.t. PrioDelay5{e in E,p in P,j in J: active_pj[p,j]>0}:    ttheta[p,j]<=M*theta[p,j];
s.t. PrioDelay6{e in E,p in P,j in J: active_pj[p,j]>0}:    (t[p,2,e]*coef[p,1]+t[p,3,e]*(1-coef[p,1]))-M*(1-theta[p,j])<=ttheta[p,j];
s.t. PrioDelay7{e in E,p in P,j in J: active_pj[p,j]>0}:    (t[p,2,e]*coef[p,1]+t[p,3,e]*(1-coef[p,1]))+M*(1-theta[p,j])>=ttheta[p,j];
s.t. PrioDelay8{e in E,p in P,j in J: active_pj[p,j]>0}:    g[p,2,e]*coef[p,1]+g[p,3,e]*(1-coef[p,1])>=(Ru[p,j]-Rl[p,j])*theta[p,j]; 
s.t. PrioDelay9{e in E,p in P,j in J: active_pj[p,j]>0}:    Ru[p,j]*theta[p,j] <= (t[p,2,e]+g[p,2,e])*coef[p,1]+(t[p,3,e]+g[p,3,e])*(1-coef[p,1]) ; 
s.t. Flexib: Flex= sum{p in P,k in K} (t[p,k,2]-t[p,k,1])*coef[p,k];
 s.t. RD: PriorityDelay=( sum{p in P,j in J, tt in T} (priorityTypeWeigth[j,tt]*active_pj[p,j]*d[p,j] ) )  + PrioWeigth[6]*(sum{p in CP1,c in C: active_coord1[p,c]>0} coordDelay1[p,c] + sum{p in CP2,c in C: active_coord2[p,c]>0} coordDelay2[p,c])  - 0.01*Flex; 
 minimize delay: PriorityDelay  ;
  
solve;  
  
printf " " > "Results.txt";  
printf "%3d  %3d \n ",SP1, SP2 >>"Results.txt";  
printf "%5.2f  %5.2f %5.2f  %5.2f \n ",init1, init2,Grn1,Grn2 >>"Results.txt";

printf " \n ">>"Results.txt";  
for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then v[p,k,1] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 } 
printf " \n ">>"Results.txt";  

for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then v[p,k,2] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 }
printf " \n ">>"Results.txt"; 

for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then g[p,k,1] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 }
printf " \n ">>"Results.txt"; 
  
for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then g[p,k,2] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 } 
printf " \n ">>"Results.txt";

printf "%3d \n ", ReqNo >>"Results.txt";  
  
for {p in P,j in J : Rl[p,j]>0}  
 {  
   printf "%d  %5.2f  %5.2f  %5.2f %d \n ", coef[p,1]*(p+10*(theta[p,j]))+(1-coef[p,1])*(p+10*(theta[p,j]+1)), Rl[p,j],Ru[p,j], d[p,j] , priorityType[j] >>"Results.txt";
 } 
printf "%3d \n ", CoordNo >>"Results.txt";  
printf "%5.2f \n ", PriorityDelay + 0.01*Flex>>"Results.txt"; 
printf "%5.2f \n ", sum{p in CP1,c in C: active_coord1[p,c]>0} coordDelay1[p,c] + sum{p in CP2,c in C: active_coord2[p,c]>0} coordDelay2[p,c]  >>"Results.txt"; 
printf "%5.2f \n ", Flex >>"Results.txt"; 
printf " \n ">>"Results.txt";




printf " " > "schedule.json";  
printf "%3d  %3d \n ",SP1, SP2 >>"Results.txt";  
printf "%5.2f  %5.2f %5.2f  %5.2f \n ",init1, init2,Grn1,Grn2 >>"Results.txt";

printf " \n ">>"Results.txt";  
for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then v[p,k,1] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 } 
printf " \n ">>"Results.txt";  

for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then v[p,k,2] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 }
printf " \n ">>"Results.txt"; 

for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then g[p,k,1] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 }
printf " \n ">>"Results.txt"; 
  
for {k in K}   
 { 
     for {p in P2} 
        { 
           printf "%5.2f  ", if(p in P)  then g[p,k,2] else 0  >>"Results.txt";   
        } 
        printf " \n ">>"Results.txt";
 } 
printf " \n ">>"Results.txt";

printf "%3d \n ", ReqNo >>"Results.txt";  
  
for {p in P,j in J : Rl[p,j]>0}  
 {  
   printf "%d  %5.2f  %5.2f  %5.2f %d \n ", coef[p,1]*(p+10*(theta[p,j]))+(1-coef[p,1])*(p+10*(theta[p,j]+1)), Rl[p,j],Ru[p,j], d[p,j] , priorityType[j] >>"Results.txt";
 } 
printf "%3d \n ", CoordNo >>"Results.txt";  
printf "%5.2f \n ", PriorityDelay + 0.01*Flex>>"Results.txt"; 
printf "%5.2f \n ", sum{p in CP1,c in C: active_coord1[p,c]>0} coordDelay1[p,c] + sum{p in CP2,c in C: active_coord2[p,c]>0} coordDelay2[p,c]  >>"Results.txt"; 
printf "%5.2f \n ", Flex >>"Results.txt"; 
printf " \n ">>"Results.txt";
end;
