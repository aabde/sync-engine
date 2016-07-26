# Nylas Sync Engine and API installation and configuration

The Nylas Sync Engine provides a RESTful API on top of a powerful email sync platform, making it easy to build apps on top of email. See the [full API documentation](https://www.nylas.com/docs/) for more details.

See API complementary documentation below to know the new endpoints and how to use them.

## Installation and Setup

### On DigitalOcean

1. Install the latest version of [Vagrant](http://www.vagrantup.com/downloads.html)

2. Install [vagrant-digitalocean plugin](https://github.com/devopsgroup-io/vagrant-digitalocean):

   `vagrant plugin install vagrant-digitalocean`

3. `git clone https://github.com/aabde/sync-engine`

4. `cd sync-engine`

5. `export DIGITAL_OCEAN_TOKEN=[Your DigitalOcean Personal Access Token]` 

5. `export DIGITAL_OCEAN_MAIL_SERVER_DOMAIN=[The domain name you want your server to be accessible at]`

6. `vagrant up --provider=digital_ocean`

7. `vagrant ssh`

8. By default the `MAIL_API_KEY` is set to `XXX`, be sure to change it in `~/.profile`

9. `/etc/init.d/launcher start`

10. check if the sync engine and the API were started correctly `/etc/init.d/launcher status`

The server is up and running. To access the server's terminal use `vagrant ssh` (to connect from another computer than the one which mounted the server use `ssh vagrant@mail.inchbase.com` after adding the ssh public key of the computer in `~/.ssh/authorized_keys` on the server)

### On a Virtual Machine

1. Install the latest versions of [Vagrant](http://www.vagrantup.com/downloads.html) and [VirtualBox](https://www.virtualbox.org/wiki/Downloads)).

2. `git clone https://github.com/aabde/sync-engine`

3. `cd sync-engine`

4. `vagrant up`

5. `vagrant ssh`

6. By default the `MAIL_API_KEY` is set to `XXX`, be sure to change it in `~/.profile`

7. `/etc/init.d/launcher start`

8. check if the sync engine and the API were started correctly `/etc/init.d/launcher status`

The server is up and running. To access the server's terminal use `vagrant ssh`

## Nylas Sync Engine

To auth an account you can either use the API endpoint /accounts/create_ (see documentation below) or via the commandline:

    bin/inbox-auth [Your account]@gmail.com

The `inbox-auth` command will walk you through the process of obtaining an authorization token from Google or another service for syncing your mail. In the open-source version of the sync engine, your credentials are stored to the local MySQL database for simplicity. The open-source Nylas Sync Engine does not support Exchange.

The sync engine will automatically begin syncing your account with the underlying provider. Note that an initial sync can take quite a while depending on how much mail you have.

## Nylas API Service

The Nylas API service provides a REST API for interacting with your data. To start it in your development environment, run command below from the `/vagrant` folder within your VM. The api should start automatically but to start it manually you run:

```bash
$ bin/inbox-api
```

The API Server runs on port 5555. At this point **You're now ready to make requests!** If you're using VirtualBox or VMWare fusion with Vagrant, port 5555 has already been forwarded to your host machine, so you can hit the API from your regular web browser.

Now you can start writing your own application on top of the Nylas API! For more information about the internals of the Nylas Sync Engine, see the [Nylas API Documentation](https://nylas.com/docs/) (Note that the Authentication section do not apply for the open-source Nylas API).

### Complementary API Documentation

If you mounted your server on DigitalOcean replace *localhost* in the following examples by the domain name of your server. 

The endpoint listing all connected accounts `http://localhost:5555/accounts` has been disabled for security reasons.

To use the API you need to pass the API key (default is `XXX` but you should have changed it) into the `X-Api-Key` header of the requests.

2 steps to connect a new account:

##### 1. Get the email address provider

method | endpoint
---:|:---
POST | http://localhost:5555/provider

###### Your app should POST a valid JSON body with the following attributes:

attribute | description
---:|:---
***email_address*** <br> *required* | The email address you want to know the provider

###### Returns a JSON with the following attributes:

attribute | description
---:|:---
***provider*** | The provider to use to register the account
***auth_url*** <br> *only if the provider is gmail* | The gmail authentication url to get an authentication code required to authenticate the account

##### 2. Register the account

method | endpoint
---:|:---
POST | http://localhost:5555/accounts/create

###### Your app should POST a valid JSON body with the following attributes (3 possibilities):

- If the provider is **gmail**:

attribute | description
---:|:---
***email_address*** <br> *required* | The email address you want to register
***provider*** <br> *required* | The provider of the email address got at the previous step
***auth_code*** <br> *required if provider is gmail* | Authentication code got at the auth_url at the previous step

- If the provider is **custom** (IMAP/SMTP):

attribute | description
---:|:---
***email_address*** <br> *required* | The email address you want to register
***provider*** <br> *required* | The provider of the email address got at the previous step
***imap_server_host*** <br> *required* | Hostname or IP address of IMAP server. e.g. *imap.mycompany.com*
***imap_server_username*** <br> *optional, default is email_address* | Username to authenticate with IMAP server
***imap_password*** <br> *required* | Password to authenticate with IMAP server
***imap_server_port*** <br> *optional, default is 993* | Port for IMAP protocol
***smtp_server_host*** <br> *required* | Hostname or IP address of SMTP server. e.g. *smtp.mycompany.com*
***smtp_server_username*** <br> *optional, default is email_address* | Username to authenticate with SMTP server
***smtp_password*** <br> *optional, default is imap_password* | Password to authenticate with SMTP server
***smtp_server_port*** <br> *optional, default is 587* | Port for SMTP protocol
***ssl_required*** <br> *optional, default is false* | Require SSL when connecting to both SMTP and IMAP

- Other providers:

attribute | description
---:|:---
***email_address*** <br> *required* | The email address you want to register
***provider*** <br> *required* | The provider of the email address got at the previous step
***password*** <br> *required if provider is not custom or gmail* | The email password

###### Returns a JSON with the following attributes:

attribute | description
---:|:---
***account_id*** | Reference to parent account object (self-referential in this case, same as id)
***email_address*** | The email address of the account
***id*** | Reference of the object
***name*** | Full name of the user, used as the default “from” name when sending mail
***object*** | A string describing the type of object (“account” in this case)
***organization_unit*** | Either *label* or *folder* depending on the provider capabilities
***provider*** | Which provider backs the account, e.g. *gmail* or *yahoo*. See [supported providers](https://nylas.com/platform/#supported_providers) for a full list (Note that *eas* is not supported by the open-source Nylas API)
***sync_state*** | The syncing status of the account. See the [sync status documentation](https://nylas.com/platform/#sync_status) for possible values.

You're done, the account is registered and synced. For requests to retreive mail, contacts, and calendar data, your app should pass the `account_id` value returned when adding the account as the "username" parameter in HTTP Basic auth. For example:

```
curl -H "X-Api-Key: [MAIL_API_KEY]" --user 'ACCOUNT_ID_VALUE_HERE:' http://localhost:5555/threads
```

If you are using a web browser and would like to clear your cached HTTP Basic Auth values, simply visit http://localhost:5555/logout and click "Cancel".

##### To delete an account

method | endpoint
---:|:---
DELETE | http://localhost:5555/account/delete

You must be authenticated with the `account_id` of the account you want to delete.

## License

This code is free software, licensed under the The GNU Affero General Public License (AGPL). See the `LICENSE` file for more details.
