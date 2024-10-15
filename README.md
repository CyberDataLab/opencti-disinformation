# OpenCTI for disinformation

This is a tunned version of OpenCTI preloaded with disinformation connectors and incidents datasets.

Currently, the DISARM Connector and the DISINFO connector are used to load some datasets found in the wild 
as STIX2 objects. 

## Installation
1. Clone the repository and access the folder.
2. Copy the `.env.example` file and name it `.env`.
3. Edit all the changeme references in the `.env` file to your chosen values.
4. Deploy the docker-compose environment:
    ```
    docker-compose up
    ```
5. Once the images are built and lauched, wait about 5-10 minutes for the system to start. 
If there is an exception on the DISINFO connector container, restart it and should work.

## Visualization
Loaded incidents can be analyzed under the `Intrusion Sets` section. 