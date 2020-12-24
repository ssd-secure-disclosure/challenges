# Welcome to our December - 2020 challenge
This challenge comes as a binary running inside a Docker with certain vulnerabilities in it!
First one to solve it, email us the solution to contact@ssd-disclosure.com for a chance to win a 100$ Amazon gift card.

Solutions should be provided in:
1. python2 or python3 (preferred) form
2. Solution should connect via port 2324 to the running Docker and obtain the `/home/ctf/flag` and display it to the person running the script
3. If you are not using existing modules, provide a `requirements.txt` file

## Notes on files under challenge folder
While the `flag`, `checker` (hash: 894b94851180f62992728605e53580e6c4ceae4b16ac9ed952918faab0b5d462), `launch.sh` are here to help you understand the challenge - they should not be modifying in any way in order to win the challenge - we will be running the original binary in our environment.


## Notes on setting on the ENV for the challenge
### Build container
```bash
sudo docker build --tag prime_checker .
```

### Run container with port 2324 being exposed
```bash
sudo docker run --detach -p 2324:2324 prime_checker
```

### Debugging 
```bash
sudo docker exec -it <container_name> bash
```
