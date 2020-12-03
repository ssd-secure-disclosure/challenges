# Notes on setting on the ENV for the challenge
# Build container
docker build --tag prime_checker .

# Run container with port 2323 being exposed
docker run --detach -p 2324:2324 prime_checker

# Debugging
# sudo docker exec -it <container_name> bash
