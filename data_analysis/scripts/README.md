# Scripts for data analysis

This folder contains the MATLAB scripts utilized to perform the analysis of the APT campaigns and the software update strategies presented in the paper.

## APT_analysis.m

This is the main script that analyze the APT campaigns in terms of products affected, attack vectors employed, and vulnerabilities exploited. It computes the effectiveness and cost of different update strategies.

### Requirements
The script calls the *agresti_coull.m*, *sort_nat.m*, and *statistics_simulation.m* scripts that must reside on the same folder.

It loads the CSV data located in the parent folder *data_analysis*.


