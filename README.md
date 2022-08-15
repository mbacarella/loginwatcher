Remote Desktop Service watcher
=====

loginwatcher is a small Windows service written in F# that protects the RDP service.

If you run an RDP service on the internet, you may noticte that it will be
dictionary attacked by bots quite ferociously. loginwatcher watches the
security log for failed login attempts, and if there are too many in too short a time,
it will ban the IP address from speaking to the server altogether.

Configuring settings
----

There are two sections to customize. Find the `Settings' module near the top of
`Worker.fs'. One group of settings are for the SMTP service. The service
will send you periodic updates on what it's doing.

Also, add a few known good IPs to `ipWhitelist'. Those will never be banned no
matter how many failed login attempts. This is mostly a sanity check so that the
admin doesn't accidentally get locked out somehow.

Note the service doesn't save a database, and it will clear all banned IPs ons
startup, so worst case scenario you can have the box rebooted to get back in.

Building
----

The build files here are for Visual Studio Code. Just click Build.

Oh, you might need the .NET tools installed.

Running
----

You can pass the `-console` flag to keep it in a command shell, or use the
service builder flags to install and uninstall in as a service.

Problems?
----

This was written for a server that we had to run on the internet temporarily. I'll be
happy to look at issues and apply PRs but I don't run this tool myself anymore,
so it may be a bit behind the latest world of F# stuff.
