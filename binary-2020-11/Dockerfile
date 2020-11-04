FROM ubuntu:xenial

ENV DEBIAN_FRONTEND noninteractive

# Update
RUN apt-get update -y && apt-get install socat -y

# Create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf
RUN mkdir /home/ctf

ADD challenge/launch.sh /home/ctf/launch.sh

# Challenge files
ADD challenge/flag /home/ctf/flag
ADD challenge/friend_net /home/ctf/friend_net

# Set some proper permissions
RUN chown -R root:ctf /home/ctf
RUN chmod 750 /home/ctf/friend_net
RUN chmod 750 /home/ctf/launch.sh
RUN chmod 440 home/ctf/flag

ENTRYPOINT /home/ctf/launch.sh
