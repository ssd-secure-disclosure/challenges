# Welcome to our November - 2020 challenge
This challenge comes as a binary running inside a Docker with certain vulnerabilities in it!
First one to solve it, email us the solution to contact@ssd-disclosure.com for a chance to win a custom gift box.

Solutions should be provided in:
1. python2 or python3 (preferred) form
2. Solution should connect via port 2323 to the running Docker and obtain the `/home/ctf/flag` and display it to the person running the script
3. If you are not using existing modules, provide a `requirements.txt` file

## Notes on files under challenge folder
While the `flag`, `friend_net` (hash: cbb7cb654080beea8241dfdd331312530c172c57d5e4604716dc1588bfee6e6b), `launch.sh` are here to help you understand the challenge - they should not be modifying in any way in order to win the challenge - we will be running the original binary in our environment.


## Notes on setting on the ENV for the challenge
### Build container
```bash
sudo docker build --tag friend_net .
```

### Run container with port 2323 being exposed
```bash
sudo docker run --detach -p 2323:2323 friend_net
```

### Debugging 
```bash
sudo docker exec -it <container_name> bash
```
