Deploying onto Kubernetes in Google Cloud
=========================================

This document guides you through the process of spinning up an example CT
personality on Google Cloud using Kubernetes and Cloud Spanner.

Prerequisites
-------------

1. You have **already** created and deployed a Trillian instance, see
   [https://github.com/google/trillian/tree/master/examples/deployment/kubernetes]
   for instructions.
1. You should have this repo checked out :)
1. A recent [Debian](https://debian.org) based distribution (other platforms
   may work, but YMMV)
1. You must have the [`jq` binary](https://packages.debian.org/stretch/jq)
   installed (for command-line manipulation of JSON)
1. You have `gcloud`/`kubectl`/`go`/`Docker` etc. installed (See
   [Cloud quickstart](https://cloud.google.com/kubernetes-engine/docs/quickstart)
   docs)
1. You have a Google account with billing configured

Process
-------

1. Ensure that you've followed the instructions
   [here](https://github.com/google/trillian/tree/master/examples/deployment/kubernetes)
   to create a Trillian instance on GCP, and have provisioned a suitable log
   tree into it.
1. Create an "all-roots.pem" file which contains all of the trusted roots you
   want your CT instance to allow.
   (e.g. `cat /etc/ssl/certs/* > /tmp/all-roots.pem`)
1. Create a `ct_server.cfg` file, use the `ct_server.cfg.example` file as a template.
   Don't forget to **change**:
   1. the `log_id:` field to contain the `tree_id` from
      the tree you provisioned into Trillian
   1. the `prefix:` to the URL path prefix where you want your log API to be served.
   1. the `public_key:` and `private_key:` entries to your own keys.
1. Run the [deploy.sh](deploy.sh) script, using the same `config.sh` file you
   used for your Trillian deployment:
  `./deploy.sh ../../../../../trillian/examples/deployment/kubernetes/config.sh`
1. The script may ask you to create a `configmap`, if so follow the
   instructions it provides to do so, not forgetting to **run the `deploy.sh`
   script again**.

The `deploy.sh` script prints out the externally available "ingress" IP when it
completes, you can use this IP and the `prefix` from your `ct_server.cfg` to
access the new CT server:

`curl http://${IP}/${PREFIX}/ct/v1/get-sth`

You may need to wait a couple of minutes for the pods to start and settle, if
you're still not getting an STH from the above request after then, check the
status of the deployment on the [console](https://console.cloud.google.com).

Updating
--------

Update the jobs by re-running the `deploy.sh` script.

If you want to change the `configmap` you'll need to:
1. Delete the old `configmap` like so: `kubectl delete configmap ctfe-configmap`
1. Create the updated `configmap` as before
1. Re-run `deploy.sh` to force kubernetes to update the pods.


