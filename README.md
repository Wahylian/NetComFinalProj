<h1>FINAL PROJECT IN NETWORK COMMUNICATIONS</h1>
<h3>By: Ido, Shachar and Lidor</h3>
<br/>
<h2>What is in the file:</h2>
1. a folder with 7 csv files for each of the 5 wireshark sniffs used in part 3 questions 1 to 3, and a csv related to question 4, and one related to the bonus question<br/>
2. a python project with the ability to generate 12 different graphs and charts for questions 1 to 3, another 3 graphs for question 4 based on the csv files,
   and another 3 graphs for the bonus question,
   and the ability to generate the csv files from the original pcapng files<br/>
3. a link to the original pcapng files, which you will have to download from google drive, as they are too heavy to upload to github even when compressed:<br/>
   the link is: https://drive.google.com/drive/folders/1aF9--1N4EBlxPKddHXaTYQeovzDNOXpL?usp=sharing<br/>
4. a folder with a png of each plot, and a pdf file with the explanation about which option in the code will produce which plot.

<h2>Instructions to run the code:</h2>
To run every function of the python file just run the program and chose the wanted option.
<h4>Note- If the csv files are not present, choose y before attempting to plot the graphs, this will create the required csv files</h4>

<h3>The Python Libraries used in this project:</h3>
1. Pandas<br/>
2. Pyshark<br/>
3. Numpy<br/>
4. matplotlib<br/>
5. seaborn<br/>

<h2>Setup instructions for pcapng files - DO BEFORE RUNNING THE PROGRAM FOR THE FIRST TIME</h2>
1. download the the files from: https://drive.google.com/drive/folders/1aF9--1N4EBlxPKddHXaTYQeovzDNOXpL?usp=sharing<br/>
2. in the folder where you have main.py and WiresharkRecordingSpecialCSV, create a folder called: 'WiresharkRecordings'<br/>
3. enter that folder and place the 7 pcapng recordings<br/>
4. run the code :)

<h2>Notes:</h2>
Matplotlib might cause some issues on windows when attempting to run the code,<br/>
* The simplest solution is, in Pycharm go to File | Settings | Tools | Python Plots | Show plots in tool window and disable that.<br/>
   Though it might break the look of the plots a bit as they could get smudged when they are not shown inside of the pycharm interface<br/>
   for a better picture of the plots, a folder with their pictures is provided<br/>
* if that happens, attempt to roll it back to versions 3.7.0 or 3.5.3 
