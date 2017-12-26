# Webhook validator and relay

The Webhook Relay is designed to receive notifications from services and relay
valid notifications to one or more hosts for processing. The Relay is presently
well-suited to validate webhooks from the following services according to the
rules below:

1. GitHub
    1. Webhook was sent from an IP address within the ranges that GitHub states
       it will use to generate notifications.
    1. Webhook includes a header that has been signed with a secret token
       assigned to the GitHub repository that is known only to its owners and
       the Relay administrator.
1. Self-hosted GitLab instances
    1. Webhook was sent from the known IP address of the GitLab instance.
    1. Webhook includes a header that contains a secret token assigned to a
       project that is known only to its owners and the Relay administrator.
1. DockerHub
    1. There are no IP restrictions on the origin of DockerHub webhooks.
    1. There are no secret tokens within DockerHub webhooks.
    1. Webhook is valid if it describes a project previously registered with
       the relay.
1. Private Docker registries (such as [GitLab Container Registry](https://docs.gitlab.com/ce/user/project/container_registry.html))
    1. Webhook was sent from the known IP address of the private Registry.
    1. Webhook includes a header that contains a secret token known only to the
       administrator of the Registry and of the Relay. This token is shared
       betweeen all projects but is unknown to them and requires no per-project
       configuration.

All webhook endpoints are obfuscated URIs such as
```
https://fqdn/dockerhub/1a7be2eb5f2045f2a475a4bc72c6a862
```

## Running

The Relay requires [docker-compose](https://docs.docker.com/compose/install/)
and, in its simplest form, can be invoked with `docker-compose up`. However, this
leaves webhook registration open to a client on the localhost testing only.

For production use, it would be wiser to protect `/`,`/info`, and `/lock`
with authentication while allowing unrestricted access to `/dockerhub`,
`/github`,`/gitlab`, and `/registry`. One might consider web-server IP
restrictions on these latter locations.

These restrictions on access could be effected through changes in the NGINX
configuration or an additional Apache proxy w/o change. An example Apache
proxy configuration is
```apache
  RequestHeader set X-Forwarded-Proto "https"

  ProxyPreserveHost On
  ProxyTimeOut 30

  ProxyPass / http://127.0.0.1:8080/
  ProxyPassReverse / http://127.0.0.1:8080/
```

## Status
The validation and relaying aspects of the code are completely functional and
should be expected to work.

However, a UI for creating the relay endpoints is only semi-functional. Both
private Docker registry and DockerHub endpoints must be created manually. To
create a DockerHub endpoint, for example:
```shell
$ uuid=$(uuid -F str)
$ docker exec webhookrelay_redis_1 redis-cli sadd ${uuid}:allowed_repos ligo/software
1
$ docker exec webhookrelay_redis_1 redis-cli sadd ${uuid}:destinations http://yourendpoint:8080
1
```
A private registry endpoint can be similarly created with keys matching
`$UUID:allowed_ip`,`$UUID:destinations`, and `$UUID:token`.

GitHub and GitLab endpoints can be created by visiting the root URL of your
Relay (recall advice to use authenticated access in production usage). An
initial obfuscated endpoint and a randomized token will be generated. Thes
should be used to configure the webhook on GitHub/GitLab. The endpoint
can then be locked or additional destinations registered. However, once
a destination is registered it cannot presently be removed except manually via
a command such as:
```shell
docker exec webhookrelay_redis_1 redis-cli srem ${uuid}:destinations http://yourendpoint:8080
```

## Long-term development
For the purposes of LIGO services that require webhooks, I am likely to
reimplement the relay functionality in the cloud. _e.g._, using the AWS API
Gateway to provide HTTP endpoints and ensure that the notification data
itself is stored in a message queue. Workers can then be installed on hosts
that directly poll the AWS message queue.
