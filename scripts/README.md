There are two scripts oin this directory, one for durumeric definition of a scan and one for the case studies.
If you want to tweak the scripts behaviour you need to tweak on the below variables, a explonation is below.
You need to have a API key for Greynoise.io for case_studies.py work as intended.

FOR THE DURUMERIC METHOD SCRIPT:
MIN_DESTINATIONS = minimum destination a source IP has probed to be counted as a scan
RATE_THRESHOLD = the minimuim packet rate to be deemed as a scan, in seconds. RATE_THRESHOLD of 10 would mean 10 packets per second
Output of the script is a CSV file with the headers= Date,Source IP,Network,Port,Distinct Destinations,Total Packets,Rate


FOR THE CASE STUDY SCRIPT:
In the below variables shapefile_path you need to add the full path to the shapefile to corretly plot geographical identicly to the bachelor thesis.
Terminal will ask for input when needed at the start, after all is set up the script will run by itself, and report on when pcap files are done analysing. 

MIN_DESTINATIONS = minimum destination a source IP has probed to be counted as a scan
RATE_THRESHOLD = the minimuim packet rate to be deemed as a scan, in seconds. RATE_THRESHOLD of 10 would mean 10 packets per second
MIN_DURATION = minimum overall duration of a scan minutes. 
MAX_RATE_THRESHOLD = the maximum packet rate in seconds. MAX_RATE_THRESHOLD of 10 would mean a MAXIMUM 10 packets per second

Output of the script is a CSV file, and two geographical heatmaps, one for benign activity and one for malicious
The csv has the headers= Date,Source IP,Network,Port,Distinct Destinations,Total Packets,Rate
