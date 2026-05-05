# mouSec-cs412-fuzzing-lab
Fuzzing campaign using AFL++ against a real-world open-source library


### Create and build the Docker container
docker build -t cs412-fuzzing .

### Run the container
docker run --rm -it -v $(pwd):/fuzzing cs412-fuzzing
