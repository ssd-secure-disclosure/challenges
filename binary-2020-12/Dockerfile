FROM ubuntu:bionic

ENV DEBIAN_FRONTEND noninteractive

# Update
RUN apt-get update -y && apt-get install socat -y
RUN apt-get install vim python-pip tmux git libssl-dev libffi-dev build-essential python-dev -y && pip install pwntools

# Create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf

# Challenge files
ADD challenge/flag /home/ctf/flag
ADD challenge/checker /home/ctf/checker
ADD challenge/ld-2.23.so /home/ctf/ld-2.23.so
ADD challenge/libc-2.23.so /home/ctf/libc-2.23.so
ADD challenge/libpthread-2.23.so /home/ctf/libpthread-2.23.so
ADD challenge/helper.sh /home/ctf/helper.sh
ADD challenge/launch.sh /home/ctf/launch.sh

# Set some proper permissions
RUN chown -R root:ctf /home/ctf
RUN chmod 750 /home/ctf/checker
RUN chmod 750 /home/ctf/launch.sh
RUN chmod 440 home/ctf/flag

USER ctf
# If people complain about the server NOT being easy enough to pop a shell on, then add a 'nice' value to it.
# Something like 'nice -5 /home/ctf/launch.sh' or add the niceness directly to the launch/helper scripts.
# https://linux.die.net/man/1/nice
ENTRYPOINT cd /home/ctf && /home/ctf/launch.sh
