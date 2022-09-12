FROM ubuntu:bionic

ENV DEBIAN_FRONTEND noninteractive

# Update
RUN apt-get update -y
RUN apt-get install -y vim tmux gdb strace gcc git
RUN apt-get install -y python3-pip socat python3

# Create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf
RUN mkdir /home/ctf

# Where to store users
RUN mkdir /home/ctf/programs/ 
RUN chmod 111 /home/ctf/programs/
RUN groupadd -r debugger && useradd -r -g debugger debugger

# Challenge files
ADD flag /home/ctf/flag
ADD MaxDebugger /home/ctf/MaxDebugger 
ADD startup.sh /home/ctf/startup.sh 
ADD program.py /home/ctf/program.py

# Set some proper permissions for the container
RUN chown -R ctf:ctf /home/ctf

# For using the flag later
RUN chown root:ctf /home/ctf/MaxDebugger

# Only the root user can RUN/open these
RUN chmod 700 /home/ctf/MaxDebugger
RUN chmod 700 /home/ctf/startup.sh
RUN chmod 700 /home/ctf/program.py
RUN chown -R root:root /home/ctf/flag 
RUN chmod 400 /home/ctf/flag

# For the entrypoint, we'll startup the daemon for reading in files
ENTRYPOINT cd /home/ctf && ./startup.sh
