# OneLogin's SAML Python Toolkit (compatible with Python3)

Installation
------------

### Dependencies ###

 *  python 3.6
 * apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
 * pip install xmlsec
 * pip install isodate
 * pip install defusedxml
 * pip install python3-saml
 * pip install tornado


***Virtualenv***

The use of virtualenv/virtualenvwrapper is highly recommended.

### Create certificates ###

in saml/cert run :
 * openssl req -new -x509 -days 3652 -nodes -out sp.crt -keyout sp.key
 * openssl req -new -x509 -days 3652 -nodes -out metadata.crt -keyout metadata.key

### Useful extesion for SAML messages ###
* [SAML Chrome Panel 1.8.9](https://chrome.google.com/webstore/detail/saml-chrome-panel/paijfdbeoenhembfhkhllainmocckace/related)



# Test with keycloack idp

Installation
------------

### Install Docker ###
* sudo apt-get remove docker docker-engine docker.io containerd runc

* sudo apt-get update

* sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common
* curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

* sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

* sudo apt-get update

* sudo apt-get install docker-ce docker-ce-cli containerd.io

* sudo docker run hello-world


### Keycloack starting ###
First run only:
* docker run --name keycloackContainer -d -p 8080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin -e DB_VENDOR=H2 jboss/keycloak

After first run:
* sudo docker start keycloackContainer

Remember to stop keycloack after usage:
* sudo docker stop keycloackContainer


### Keycloack useful urls ###
* master: http://localhost:8080/auth/admin
* users: http://localhost:8080/auth/realms/idp_dacd/account/
* saml request: http://localhost:8080/auth/realms/idp_dacd/protocol/saml
* metadata: http://localhost:8080/auth/realms/idp_dacd/protocol/saml/descriptor





