<h1>FINAL PROJECT IN NETWORK COMMUNICATIONS</h1>
<h3>By: Ido, Shachar and Lidor</h3>
<br/>
<h2>What is in the file:</h2>
1. A pdf with detailed answers for each of the proposed questions: 'Final Project ComNet.pdf'.<br/>
2. src folder with the following:<br/>
   a. a folder with 7 csv files for each of the 5 wireshark sniffs used in part 3 questions 1 to 3, and a csv related to question 4, and one related to the bonus question-
      This folder is called 'WiresharkRecordingSpecialCSV'.<br/>
   b. a python project called 'main' with the ability to generate 12 different graphs and charts for questions 1 to 3, another 3 graphs for question 4 based on the csv files,
      and another 3 graphs for the bonus question, and the ability to generate the csv files from the original pcapng files.<br/>
3. res folder with the following:<br/>
   a. a png of each plot created in the program.<br/>
   b. and a pdf file called 'PlotsDictionary.pdf' with the explanation about which option in the code will produce which plot .<br/>

<h2>Setup instructions for pcapng files - DO BEFORE RUNNING THE PROGRAM</h2>
1. download the the files from: https://drive.google.com/drive/folders/1aF9--1N4EBlxPKddHXaTYQeovzDNOXpL?usp=sharing<br/>
2. in the folder (the folder named /src/) where you have main.py and WiresharkRecordingSpecialCSV, create a folder called: 'WiresharkRecordings'<br/>
3. enter that folder and place the 7 pcapng recordings<br/>
4. run the code :)

<h2>Instructions to run the code:</h2>
To run every function of the python file just run the program and chose the wanted option.<br/>
<h4>Note- If the csv files are not present, choose y before attempting to plot the graphs, this will create the required csv files</h4>

<h2>The Python Libraries used in this project:</h2>
1. Pandas<br/>
2. Pyshark<br/>
3. Numpy<br/>
4. matplotlib<br/>
5. seaborn<br/>
6. os<br/>

<h2>Notes and Additiona Information:</h2>
1. Matplotlib might cause some issues on windows when attempting to run the code, there are multiple solutions we found on the web:<br/>
* The simplest solution is, in Pycharm go to File | Settings | Tools | Python Plots | Show plots in tool window and disable that.<br/>
   Though it might break the look of the plots a bit as they could get smudged when they are not shown inside of the pycharm interface<br/>
   for a better picture of the plots, a folder with their pictures is provided (in /res/)<br/>
* Another solution is, attempt to roll matplotlib back to versions 3.7.0 or 3.5.3 <br/>
2. Our LinkedIn Profiles are:<br/>
* Ido: https://www.linkedin.com/in/ido-ron-35b606354 <br/>
* Shachar: http://www.linkedin.com/in/shacharts-undefined-38a600354 <br/>
* Lidor: https://www.linkedin.com/in/lidor-ayhoni-a71826266
