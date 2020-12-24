FROM ubuntu:xenial 

ENV DEBIAN_FRONTEND noninteractive

# Update
RUN apt-get update -y && apt-get upgrade -y && apt-get install socat -y
RUN apt-get install vim python-pip tmux git libssl-dev libffi-dev build-essential python-dev -y && pip install pwntools

# Create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf

# Challenge files
ADD challenge/flag /home/ctf/flag
ADD challenge/cobra_kai /home/ctf/cobra_kai
ADD challenge/ld.so /home/ctf/ld.so
ADD challenge/libc.so /home/ctf/libc.so
ADD challenge/helper.sh /home/ctf/helper.sh
ADD challenge/launch.sh /home/ctf/launch.sh

# Set some proper permissions
RUN chown -R root:ctf /home/ctf
RUN chmod 750 /home/ctf/cobra_kai
RUN chmod 750 /home/ctf/launch.sh
RUN chmod 750 /home/ctf/helper.sh
RUN chmod 440 home/ctf/flag

USER ctf
ENTRYPOINT cd /home/ctf && /home/ctf/launch.sh
