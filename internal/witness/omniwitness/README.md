
## A CT omniwitness

This docker configuration allows a witness to be deployed that witnesses STHs
for all usable CT logs.  The witness obtains a new STH from these logs every 
10 seconds and exposes port 8100 outside the container, meaning it could also be
used to distribute the cosigned STHs.

### Configuration

The only file that needs to be edited is the `.env` file.  In particular, it
should be populated with a PEM-encoded `WITNESS_PRIVATE_KEY`.

### Running

From the directory containing the `docker-compose.yaml` file, run
`docker-compose up -d`.  After a few minutes both the feeder and the witness 
processes should be running inside the container.
