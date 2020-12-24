# Notes on setting on the ENV for the challenge
# Build container
sudo docker build --tag cobra_kai .

# Run container with port 2325 being exposed
sudo docker run --detach -p 2325:2325 cobra_kai

# Debugging
# sudo docker exec -it <container_name> bash
