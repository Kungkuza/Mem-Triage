Mem-Triage
Author: David James Garner
Made with an AI Baseline from ChatGPT

The set-up process is straightforward. To pull down and use the software please first; 

Ensure you have the following prerequisites: 

- A Windows 10 or 11 system with GitBash 

- Python 3.10 or newer (3.14.5 used) 

- A memory dumping tool like FTK Imager 

Notes: Tool was produced in a VSCode environment. 

Steps to follow once prerequisites are met: 

Use this GitHub link to find the repository and source code: https://github.com/Kungkuza/Mem-Triage.git

Download/pull the code. 

Use GitBash to supply the dependencies required by typing this within the working directory: py –m pip install pefile capa colorama pyinstaller . Additionally, to install Volatility3 in the same directory, use: git clone https://github.com/volatilityfoundation/volatility3.git 

Change the pathing of the VOLATILITY_PATH variable in config.py to the “\\volatility3\\vol.py” with the correct pathing with double slashes from your system preceding that to allow for vol.py to be used. This is a known item to fix to become dynamic. 

The type of file format needed to be used by Mem-Triag is .mem, download memory dumping tools like FTK Imager to produce this file. 

Depending on how this file is titled, modify the value of the MEMORY_IMAGE variable with the name of the .mem file, and move the file into the working directory of the tool. 

Execute the tool by clicking on main.py and running the code, or by forcing the use of (if needed) of Python version 3.14 by typing in py –3.14 main.py . 