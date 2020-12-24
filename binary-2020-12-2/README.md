# Welcome to our 2nd December - 2020 challenge
This challenge comes as a binary running inside a Docker with certain vulnerabilities in it!
First one to solve it, email us the solution to contact@ssd-disclosure.com for a chance to win a 100$ Amazon gift card.

Solutions should be provided in:
1. python2 or python3 (preferred) form
2. Solution should connect via port 2325 to the running Docker and obtain the `/home/ctf/flag` and display it to the person running the script
3. If you are not using existing modules, provide a `requirements.txt` file

## Notes on files under challenge folder
While the `flag`, `cobra_kai` (hash: ad7d8b289a56764bd96d3f52056b23662dbd5c41602482af8d94903504912d86), `launch.sh` are here to help you understand the challenge - they should not be modifying in any way in order to win the challenge - we will be running the original binary in our environment.


## Notes on setting on the ENV for the challenge
### Build container
```bash
sudo docker build --tag cobra_kai .
```

### Run container with port 2325 being exposed
```bash
sudo docker run --detach -p 2325:2325 cobra_kai
```

### Debugging 
```bash
sudo docker exec -it <container_name> bash
```
